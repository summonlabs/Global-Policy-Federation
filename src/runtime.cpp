#include "gpf/runtime.hpp"

#include "gpf/platform.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace gpf {
namespace {

void set_reason(std::string* target, const std::string& value) {
  if (target != nullptr) *target = value;
}

}  // namespace

const char* site_event_kind_name(SiteEventKind kind) noexcept {
  switch (kind) {
    case SiteEventKind::StoreOpened: return "store-opened";
    case SiteEventKind::BundleAccepted: return "bundle-accepted";
    case SiteEventKind::BundleRejected: return "bundle-rejected";
    case SiteEventKind::OverrideRegistered: return "override-registered";
    case SiteEventKind::OverrideRefused: return "override-refused";
    case SiteEventKind::PolicyApplied: return "policy-applied";
    case SiteEventKind::ConflictRecorded: return "conflict-recorded";
    case SiteEventKind::Connected: return "connected";
    case SiteEventKind::Disconnected: return "disconnected";
    case SiteEventKind::ReceiptsReported: return "receipts-reported";
    case SiteEventKind::Shutdown: return "shutdown";
    case SiteEventKind::CallbackFailed: return "callback-failed";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------------------
// SiteRuntime
// ---------------------------------------------------------------------------------------

SiteRuntime::SiteRuntime() = default;

SiteRuntime::~SiteRuntime() {
  auto status = shutdown();
  (void)status;
}

Result<std::unique_ptr<SiteRuntime>> SiteRuntime::open(const SiteConfig& config) {
  if (config.federation.is_nil() || config.member.is_nil() || config.site.is_nil()) {
    return Result<std::unique_ptr<SiteRuntime>>::failure(
        ErrorCode::InvalidArgument, "site configuration needs federation, member and site identities");
  }
  if (config.worker_threads == 0 || config.worker_threads > limits::kMaxWorkerThreads) {
    return Result<std::unique_ptr<SiteRuntime>>::failure(
        ErrorCode::InvalidArgument, "worker thread count is outside the supported range",
        std::to_string(config.worker_threads));
  }
  StoreOpenOptions options;
  options.directory = config.store_directory;
  options.identity.federation = config.federation;
  options.identity.member = config.member;
  options.identity.site = config.site;
  options.identity.created_at = Timestamp{platform::system_now_millis()};
  IdGenerator generator(config.id_seed);
  options.identity.id.value = generator.next();

  auto store = DurableStore::open(options);
  if (!store.ok()) return Result<std::unique_ptr<SiteRuntime>>::failure(store.error);

  auto runtime = std::unique_ptr<SiteRuntime>(new SiteRuntime());
  runtime->config_ = config;
  runtime->store_ = std::make_unique<DurableStore>(std::move(*store.value));
  auto replayed = replay_records(runtime->store_->identity(), runtime->store_->records());
  if (!replayed) return Result<std::unique_ptr<SiteRuntime>>::failure(replayed.error);
  runtime->state_ = std::move(*replayed.value);
  runtime->state_.identity = runtime->store_->identity();
  runtime->ledger_.set_federation(config.federation);
  runtime->ledger_.set_root_member(config.root_member.is_nil() ? config.member : config.root_member);
  runtime->pending_receipts_ = runtime->state_.receipts;
  runtime->last_contact_at_ = runtime->state_.last_federation_contact;
  runtime->status_.store_epoch = runtime->store_->epoch();
  runtime->status_.authority_epoch = runtime->state_.authority_epoch;
  runtime->status_.accepted_bundles = runtime->state_.accepted_bundles.size();
  runtime->status_.local_bundles = runtime->state_.local_bundles.size();
  runtime->status_.overrides = runtime->state_.overrides.size();
  runtime->status_.receipts = runtime->state_.receipts.size();
  runtime->status_.conflicts = runtime->state_.conflicts.size();
  runtime->status_.pending_receipts = runtime->pending_receipts_.size();
  runtime->status_.applied_global_generation = runtime->state_.applied_global_generation;
  runtime->status_.local_generation = runtime->state_.local_generation;
  if (runtime->state_.has_catalog) runtime->catalog_ = runtime->state_.catalog;
  runtime->start_workers();
  runtime->emit(SiteEvent{SiteEventKind::StoreOpened, recovery_outcome_name(runtime->store_->recovery().outcome),
                          runtime->store_->recovery().detail, PolicyBundleId{}, OverrideId{},
                          Generation{}, runtime->store_->recovery().records_replayed});
  return Result<std::unique_ptr<SiteRuntime>>::success(std::move(runtime));
}

void SiteRuntime::start_workers() {
  workers_started_ = true;
  const std::size_t count = config_.worker_threads;
  workers_.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    workers_.emplace_back([this] { worker_loop(); });
  }
  status_.worker_threads = count;
}

void SiteRuntime::stop_workers() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
    status_.stopping = true;
    queue_.clear();
  }
  work_available_.notify_all();
  // Workers are joined without holding the state lock: they only need the queue lock to finish.
  for (std::thread& worker : workers_) {
    if (worker.joinable()) worker.join();
  }
  workers_.clear();
  workers_started_ = false;
}

Status SiteRuntime::shutdown() {
  stop_workers();
  if (socket_ != nullptr) {
    socket_->close();
    socket_.reset();
  }
  if (store_ != nullptr) {
    const Status status = store_->close();
    if (!status.ok()) return status;
  }
  emit(SiteEvent{SiteEventKind::Shutdown, "shutdown", "site runtime stopped", PolicyBundleId{},
                 OverrideId{}, Generation{}, status_.receipts});
  return Status::success();
}

void SiteRuntime::set_listener(SiteEventListener listener) {
  std::lock_guard<std::mutex> lock(mutex_);
  listener_ = std::move(listener);
}

void SiteRuntime::set_membership(MembershipBinding membership) {
  std::lock_guard<std::mutex> lock(mutex_);
  membership_ = std::move(membership);
}

void SiteRuntime::emit(const SiteEvent& event) const {
  SiteEventListener listener;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    listener = listener_;
  }
  if (!listener) return;
  try {
    listener(event);
  } catch (...) {
    // A throwing callback is contained here: it must never unwind through a locked region or
    // through a caller that is committing durable state.
  }
}

void SiteRuntime::worker_loop() {
  while (true) {
    std::shared_ptr<CompileTask> task;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      work_available_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
      if (stopping_ && queue_.empty()) return;
      task = queue_.front();
      queue_.pop_front();
      status_.queued_tasks = queue_.size();
    }
    if (task == nullptr) continue;
    CompileTask local = *task;
    Result<EffectivePolicy> result = build_effective(local);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      task->result = std::move(result);
      task->done = true;
    }
    work_finished_.notify_all();
  }
}

Result<EffectivePolicy> SiteRuntime::build_effective(const CompileTask& task) const {
  EffectivePolicyInput input;
  input.federation = task.state.identity.federation;
  input.member = task.state.identity.member;
  input.site = task.state.identity.site;
  input.now = task.now;
  input.accepted_bundles = task.state.accepted_bundles;
  input.local_bundles = task.state.local_bundles;
  input.overrides = task.state.overrides;
  input.capabilities = task.state.capabilities;
  input.capability_catalog = task.catalog;
  input.runtime_version = config_.runtime_version;
  input.authority = &task.ledger;
  input.membership = &task.membership;
  input.partitioned = task.partitioned;
  input.last_contact_at = task.last_contact_at;
  // Bundles are verified when they are accepted and again when durable state is replayed, so the
  // compiler validates structure without recomputing the same digests on every activation.
  input.verify_bundle_integrity = false;
  // Qualified: the member function of the same name takes a clock, not an input structure.
  return gpf::compile_effective_policy(input);
}

Result<EffectivePolicy> SiteRuntime::compile_effective_policy(Timestamp now) {
  auto task = std::make_shared<CompileTask>();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stopping_) {
      return Result<EffectivePolicy>::failure(ErrorCode::Cancelled, "runtime is stopping");
    }
    if (queue_.size() >= limits::kMaxQueueDepth) {
      return Result<EffectivePolicy>::failure(ErrorCode::Busy, "compilation queue is full");
    }
    task->state = state_;
    task->membership = membership_;
    task->catalog = catalog_;
    task->ledger = ledger_;
    task->store_epoch = store_ != nullptr ? store_->epoch() : Epoch{};
    task->global_generation = state_.applied_global_generation;
    task->local_generation = state_.local_generation;
    task->now = now;
    task->partitioned = !status_.connected;
    task->last_contact_at = last_contact_at_;
    queue_.push_back(task);
    status_.queued_tasks = queue_.size();
  }
  work_available_.notify_one();

  std::unique_lock<std::mutex> lock(mutex_);
  work_finished_.wait(lock, [&] { return task->done || stopping_; });
  if (!task->done) {
    return Result<EffectivePolicy>::failure(ErrorCode::Cancelled,
                                            "compilation was abandoned because the runtime stopped");
  }
  if (task->store_epoch != store_->epoch()) {
    ++status_.stale_compilations;
    return Result<EffectivePolicy>::failure(
        ErrorCode::Fenced, "compilation result belongs to an earlier store epoch",
        std::to_string(task->store_epoch.value) + " vs " + std::to_string(store_->epoch().value));
  }
  if (task->global_generation != state_.applied_global_generation ||
      task->local_generation != state_.local_generation) {
    ++status_.stale_compilations;
    return Result<EffectivePolicy>::failure(
        ErrorCode::StaleGeneration, "state moved on while the compilation was running",
        std::to_string(task->global_generation.value) + "/" +
            std::to_string(task->local_generation.value));
  }
  ++status_.compilations;
  if (!task->result.ok()) return Result<EffectivePolicy>::failure(task->result.error);
  return task->result;
}
Status SiteRuntime::append_receipt_locked(Receipt receipt, Timestamp now) {
  if (state_.receipts.size() >= limits::kMaxReceiptsPerSite) {
    return Status::failure(ErrorCode::TooLarge, "receipt log exceeds the configured limit",
                           std::to_string(state_.receipts.size()));
  }
  // Receipt identities are derived from the decision itself, so recording the same decision twice
  // is one receipt rather than two: duplicated delivery cannot inflate the evidence trail.
  const ReceiptId derived = derive_receipt_id(receipt);
  for (const Receipt& existing : state_.receipts) {
    if (existing.id == derived) return Status::success();
  }
  receipt.id = derived;
  receipt.sequence = state_.next_receipt_sequence;
  auto next = state_.next_receipt_sequence.next();
  if (!next) return Status::failure(next.error);
  const Status sealed = seal_receipt(receipt);
  if (!sealed.ok()) return sealed;
  const std::string payload = encode_receipt_record(receipt);
  const Status appended =
      store_->append(StoreRecordKind::ReceiptAppended, payload, now);
  if (!appended.ok()) return appended;
  StoreRecord record;
  record.kind = StoreRecordKind::ReceiptAppended;
  record.writer_epoch = store_->epoch();
  record.sequence = store_->last_sequence();
  record.payload = payload;
  record.payload_digest = Sha256::hash(payload);
  bool applied = false;
  const Status status = apply_record(state_, record, applied);
  if (!status.ok()) return status;
  state_.next_receipt_sequence = *next;
  pending_receipts_.push_back(receipt);
  status_.receipts = state_.receipts.size();
  status_.pending_receipts = pending_receipts_.size();
  return Status::success();
}

bool SiteRuntime::authority_allows_bundle_locked(const PolicyBundle& bundle, Timestamp now,
                                                 std::string* reason) const {
  bool has_mandatory = false;
  bool has_non_mandatory = false;
  std::vector<std::string> domains;
  for (const Rule& rule : bundle.rules) {
    if (rule.rule_class == RuleClass::Mandatory) {
      has_mandatory = true;
    } else {
      has_non_mandatory = true;
    }
    if (std::find(domains.begin(), domains.end(), rule.domain) == domains.end()) {
      domains.push_back(rule.domain);
    }
  }
  const std::string domain = domains.size() == 1 ? domains.front() : std::string();
  if (has_mandatory) {
    const AuthorityDecision decision = ledger_.evaluate(bundle.issuer_member,
                                                        AuthorityAction::PublishMandatory, bundle.scope,
                                                        domain, now, &membership_);
    if (!decision.granted()) {
      set_reason(reason, std::string("publish-mandatory:") + authority_outcome_name(decision.outcome));
      return false;
    }
  }
  if (has_non_mandatory) {
    const AuthorityDecision decision = ledger_.evaluate(bundle.issuer_member,
                                                        AuthorityAction::PublishPolicy, bundle.scope,
                                                        domain, now, &membership_);
    if (!decision.granted()) {
      set_reason(reason, std::string("publish-policy:") + authority_outcome_name(decision.outcome));
      return false;
    }
  }
  if (!has_mandatory && !has_non_mandatory) {
    // An empty bundle still needs an explicit right to publish.
    const AuthorityDecision decision = ledger_.evaluate(bundle.issuer_member,
                                                        AuthorityAction::PublishPolicy, bundle.scope,
                                                        std::string(), now, &membership_);
    if (!decision.granted()) {
      set_reason(reason, std::string("publish-policy:") + authority_outcome_name(decision.outcome));
      return false;
    }
  }
  return true;
}

Status SiteRuntime::accept_bundle(const PolicyBundle& bundle, bool* accepted, std::string* reason_code) {
  if (accepted != nullptr) *accepted = false;
  const Status integrity = verify_bundle(bundle);
  if (!integrity.ok()) {
    set_reason(reason_code, "integrity-failure");
    emit(SiteEvent{SiteEventKind::BundleRejected, "integrity-failure", integrity.error.message, bundle.id,
                   OverrideId{}, bundle.global_generation, 0});
    return Status::success();
  }
  std::string denial;
  // The event is decided while the state is locked and delivered only after the lock is released:
  // emit() takes the state lock itself, so emitting from inside a locked region would deadlock.
  bool denied = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundle.federation != config_.federation) {
      set_reason(reason_code, "wrong-federation");
      return Status::success();
    }
    if (!bundle_applies_to_site(bundle, config_.member, config_.site)) {
      set_reason(reason_code, "not-applicable");
      return Status::success();
    }
    if (!authority_allows_bundle_locked(bundle, Timestamp{platform::system_now_millis()}, &denial)) {
      set_reason(reason_code, reasons::kAuthorityDenied);
      Receipt receipt;
      receipt.federation = config_.federation;
      receipt.member = config_.member;
      receipt.site = config_.site;
      receipt.bundle = bundle.id;
      receipt.global_generation = bundle.global_generation;
      receipt.kind = ReceiptKind::Rejected;
      receipt.reason_code = reasons::kAuthorityDenied;
      receipt.detail = denial;
      receipt.bundle_digest = bundle.integrity_digest;
      const Status recorded = append_receipt_locked(receipt, Timestamp{platform::system_now_millis()});
      if (!recorded.ok()) return recorded;
      denied = true;
    }
    if (denied) {
      // Reported after the lock is released, below.
    } else {
    for (const PolicyBundle& existing : state_.accepted_bundles) {
      if (existing.id == bundle.id) {
        if (existing.integrity_digest == bundle.integrity_digest) {
          if (accepted != nullptr) *accepted = true;
          set_reason(reason_code, "already-accepted");
          return Status::success();
        }
        set_reason(reason_code, "divergent-content");
        return Status::success();
      }
    }
    const std::string payload = encode_bundle_record(bundle);
    const Status appended = store_->append(StoreRecordKind::BundleAccepted, payload,
                                           Timestamp{platform::system_now_millis()});
    if (!appended.ok()) return appended;
    StoreRecord record;
    record.kind = StoreRecordKind::BundleAccepted;
    record.writer_epoch = store_->epoch();
    record.sequence = store_->last_sequence();
    record.payload = payload;
    record.payload_digest = Sha256::hash(payload);
    bool applied = false;
    const Status status = apply_record(state_, record, applied);
    if (!status.ok()) return status;
    status_.accepted_bundles = state_.accepted_bundles.size();
    status_.applied_global_generation = state_.applied_global_generation;
    if (accepted != nullptr) *accepted = true;
    set_reason(reason_code, "accepted");
    Receipt receipt;
    receipt.federation = config_.federation;
    receipt.member = config_.member;
    receipt.site = config_.site;
    receipt.bundle = bundle.id;
    receipt.global_generation = bundle.global_generation;
    receipt.kind = ReceiptKind::Accepted;
    receipt.reason_code = "accepted";
    receipt.detail = "bundle accepted for activation";
    receipt.bundle_digest = bundle.integrity_digest;
    const Status recorded = append_receipt_locked(receipt, Timestamp{platform::system_now_millis()});
    if (!recorded.ok()) return recorded;
    }
  }
  if (denied) {
    emit(SiteEvent{SiteEventKind::BundleRejected, reasons::kAuthorityDenied, denial, bundle.id,
                   OverrideId{}, bundle.global_generation, 0});
    return Status::success();
  }
  emit(SiteEvent{SiteEventKind::BundleAccepted, "accepted", "bundle accepted", bundle.id, OverrideId{},
                 bundle.global_generation, 1});
  return Status::success();
}

Status SiteRuntime::register_override(const LocalOverride& record, bool* accepted,
                                      std::string* reason_code) {
  if (accepted != nullptr) *accepted = false;
  const Status validity = validate_override(record);
  if (!validity.ok()) {
    set_reason(reason_code, "invalid-override");
    return validity;
  }
  auto computed = compute_override_digest(record);
  if (!computed) return Status::failure(computed.error);
  if (*computed != record.digest) {
    set_reason(reason_code, "integrity-failure");
    return Status::failure(ErrorCode::IntegrityFailure, "override digest does not match content");
  }
  bool without_base = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (record.federation != config_.federation || record.member != config_.member ||
        record.site != config_.site) {
      set_reason(reason_code, "wrong-site");
      return Status::success();
    }
    const PolicyBundle* base = state_.find_bundle(record.target_bundle);
    if (base == nullptr || base->global_generation != record.target_bundle_generation ||
        base->integrity_digest != record.target_bundle_digest) {
      // An override must be bound to a generation this site actually holds. Without that base it
      // is not a local exception, it is an unattributable claim.
      set_reason(reason_code, reasons::kOverrideWithoutBase);
      without_base = true;
    } else {
      for (const LocalOverride& existing : state_.overrides) {
        if (existing.id == record.id) {
          if (existing.digest == record.digest) {
            if (accepted != nullptr) *accepted = true;
            set_reason(reason_code, "already-registered");
            return Status::success();
          }
          set_reason(reason_code, "divergent-content");
          return Status::success();
        }
      }
      if (state_.overrides.size() >= limits::kMaxOverridesPerSite) {
        return Status::failure(ErrorCode::TooLarge, "override log exceeds the configured limit");
      }
      const std::string payload = encode_override_record(record);
      const Status appended =
          store_->append(StoreRecordKind::OverrideRegistered, payload, record.created_at);
      if (!appended.ok()) return appended;
      StoreRecord stored;
      stored.kind = StoreRecordKind::OverrideRegistered;
      stored.writer_epoch = store_->epoch();
      stored.sequence = store_->last_sequence();
      stored.payload = payload;
      stored.payload_digest = Sha256::hash(payload);
      bool applied = false;
      const Status status = apply_record(state_, stored, applied);
      if (!status.ok()) return status;
      status_.overrides = state_.overrides.size();
      status_.local_generation = state_.local_generation;
      if (accepted != nullptr) *accepted = true;
      set_reason(reason_code, "registered");
    }
  }
  if (without_base) {
    emit(SiteEvent{SiteEventKind::OverrideRefused, reasons::kOverrideWithoutBase,
                   "no accepted generation matches the override's binding", record.target_bundle,
                   record.id, record.target_bundle_generation, 0});
    return Status::success();
  }
  emit(SiteEvent{SiteEventKind::OverrideRegistered, "registered", "local override registered",
                 record.target_bundle, record.id, record.local_generation, 1});
  return Status::success();
}

Status SiteRuntime::record_receipt(const Receipt& receipt) {
  std::lock_guard<std::mutex> lock(mutex_);
  return append_receipt_locked(receipt, receipt.at);
}

Status SiteRuntime::set_capabilities(const SiteCapabilitySnapshot& snapshot) {
  const Status validity = validate_capability_snapshot(snapshot);
  if (!validity.ok()) return validity;
  std::lock_guard<std::mutex> lock(mutex_);
  const std::string payload = encode_capability_record(snapshot);
  const Timestamp now{platform::system_now_millis()};
  const Status appended = store_->append(StoreRecordKind::CapabilitySnapshotUpdated, payload, now);
  if (!appended.ok()) return appended;
  StoreRecord record;
  record.kind = StoreRecordKind::CapabilitySnapshotUpdated;
  record.writer_epoch = store_->epoch();
  record.sequence = store_->last_sequence();
  record.payload = payload;
  record.payload_digest = Sha256::hash(payload);
  bool applied = false;
  return apply_record(state_, record, applied);
}

Status SiteRuntime::ingest_sync(const SyncResponseMessage& response, Timestamp now,
                                std::size_t* accepted_count, std::size_t* rejected_count) {
  std::vector<PolicyBundle> candidates;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    last_contact_at_ = now;
    if (response.has_catalog) {
      const Status validity = validate_capability_catalog(response.catalog);
      if (!validity.ok()) return validity;
      // The catalog is durable site state, not a transient cache: after a restart during a
      // partition the site must still know which capabilities exist so that "unsupported" and
      // "not yet told" stay different answers.
      if (!state_.has_catalog || state_.catalog.generation < response.catalog.generation) {
        catalog_ = response.catalog;
        const std::string payload = encode_catalog_record(response.catalog);
        const Status appended =
            store_->append(StoreRecordKind::CapabilityCatalogUpdated, payload, now);
        if (!appended.ok()) return appended;
        StoreRecord catalog_record;
        catalog_record.kind = StoreRecordKind::CapabilityCatalogUpdated;
        catalog_record.writer_epoch = store_->epoch();
        catalog_record.sequence = store_->last_sequence();
        catalog_record.payload = payload;
        catalog_record.payload_digest = Sha256::hash(payload);
        bool catalog_applied = false;
        const Status catalog_status = apply_record(state_, catalog_record, catalog_applied);
        if (!catalog_status.ok()) return catalog_status;
      } else {
        catalog_ = state_.catalog;
      }
    } else if (state_.has_catalog) {
      catalog_ = state_.catalog;
    }
    for (const AuthorityGrant& grant : response.grants) {
      bool present = false;
      for (const AuthorityGrant& existing : state_.grants) {
        if (existing.id == grant.id) {
          present = true;
          break;
        }
      }
      if (!present) {
        const std::string payload = encode_grant_record(grant);
        const Status appended = store_->append(StoreRecordKind::AuthorityGrantAdded, payload, now);
        if (!appended.ok()) return appended;
        StoreRecord record;
        record.kind = StoreRecordKind::AuthorityGrantAdded;
        record.writer_epoch = store_->epoch();
        record.sequence = store_->last_sequence();
        record.payload = payload;
        record.payload_digest = Sha256::hash(payload);
        bool applied = false;
        const Status status = apply_record(state_, record, applied);
        if (!status.ok()) return status;
      }
    }
    for (const RevocationRecord& revocation : response.revocations) {
      bool present = false;
      for (const RevocationRecord& existing : state_.revocations) {
        if (existing.id == revocation.id) {
          present = true;
          break;
        }
      }
      if (!present) {
        const std::string payload = encode_revocation_record(revocation);
        const Status appended = store_->append(StoreRecordKind::RevocationApplied, payload, now);
        if (!appended.ok()) return appended;
        StoreRecord record;
        record.kind = StoreRecordKind::RevocationApplied;
        record.writer_epoch = store_->epoch();
        record.sequence = store_->last_sequence();
        record.payload = payload;
        record.payload_digest = Sha256::hash(payload);
        bool applied = false;
        const Status status = apply_record(state_, record, applied);
        if (!status.ok()) return status;
      }
    }
    // Rebuild the authority ledger from persisted grants and revocations, then answer the one
    // question the site needs: may this publisher publish this policy?
    ledger_.restore(state_.grants, state_.revocations, state_.authority_epoch, now);
    ledger_.set_federation(config_.federation);
    ledger_.set_root_member(config_.root_member.is_nil() ? config_.member : config_.root_member);
    for (const PolicyBundle& bundle : response.bundles) {
      candidates.push_back(bundle);
    }
    status_.authority_epoch = state_.authority_epoch;
  }

  std::size_t accepted = 0;
  std::size_t rejected = 0;
  for (const PolicyBundle& bundle : candidates) {
    bool was_accepted = false;
    std::string reason;
    const Status status = accept_bundle(bundle, &was_accepted, &reason);
    if (!status.ok()) return status;
    if (was_accepted) {
      ++accepted;
    } else if (reason != "already-accepted" && reason != "not-applicable") {
      ++rejected;
    }
  }
  if (accepted_count != nullptr) *accepted_count = accepted;
  if (rejected_count != nullptr) *rejected_count = rejected;
  return Status::success();
}
Result<EffectivePolicy> SiteRuntime::activate(Timestamp now, std::size_t* receipts_recorded) {
  auto compiled = compile_effective_policy(now);
  if (!compiled) return compiled;
  std::lock_guard<std::mutex> lock(mutex_);
  const std::string payload = encode_generation_record(state_.applied_global_generation,
                                                       state_.local_generation, last_contact_at_);
  const Status appended = store_->append(StoreRecordKind::BundleActivated, payload, now);
  if (!appended.ok()) return Result<EffectivePolicy>::failure(appended.error);
  StoreRecord record;
  record.kind = StoreRecordKind::BundleActivated;
  record.writer_epoch = store_->epoch();
  record.sequence = store_->last_sequence();
  record.payload = payload;
  record.payload_digest = Sha256::hash(payload);
  bool applied = false;
  const Status status = apply_record(state_, record, applied);
  if (!status.ok()) return Result<EffectivePolicy>::failure(status.error);

  std::size_t recorded = 0;
  for (const Receipt& receipt : compiled->receipts) {
    if (state_.receipts.size() >= limits::kMaxReceiptsPerSite) break;
    bool duplicate = false;
    for (const Receipt& existing : state_.receipts) {
      if (existing.id == receipt.id) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) continue;
    const Status receipt_status = append_receipt_locked(receipt, now);
    if (!receipt_status.ok()) return Result<EffectivePolicy>::failure(receipt_status.error);
    ++recorded;
  }
  status_.local_generation = state_.local_generation;
  status_.applied_global_generation = state_.applied_global_generation;
  if (receipts_recorded != nullptr) *receipts_recorded = recorded;
  return compiled;
}

Status SiteRuntime::connect(const std::string& host, std::uint16_t port) {
  auto socket = net::Socket::connect(host, port);
  if (!socket.ok()) {
    disconnect(socket.error.message);
    return Status::failure(socket.error);
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (socket_ != nullptr) socket_->close();
    socket_ = std::make_unique<net::Socket>(std::move(*socket.value));
    status_.connected = true;
    status_.partitioned = false;
    last_contact_at_ = Timestamp{platform::system_now_millis()};
  }
  emit(SiteEvent{SiteEventKind::Connected, "connected", host + ":" + std::to_string(port), PolicyBundleId{},
                 OverrideId{}, Generation{}, 1});
  return Status::success();
}

Status SiteRuntime::sync_once(Timestamp now, std::size_t* accepted_count, std::size_t* rejected_count) {
  HelloMessage hello;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (socket_ == nullptr) {
      return Status::failure(ErrorCode::NotConnected, "site is not connected to the federation");
    }
    hello.federation = config_.federation;
    hello.member = config_.member;
    hello.site = config_.site;
    hello.site_epoch = store_->epoch();
    hello.local_generation = state_.local_generation;
    hello.applied_global_generation = state_.applied_global_generation;
    hello.runtime_version = config_.runtime_version;
    hello.capabilities = state_.capabilities;
  }
  SequenceNumber request{1};
  const Status sent = socket_->send_frame(encode_frame(make_envelope(MessageType::Hello, request, hello_to_json(hello))));
  if (!sent.ok()) {
    disconnect("hello could not be sent");
    return sent;
  }
  auto welcome_frame = socket_->receive_frame(limits::kMaxWireMessageBytes);
  if (!welcome_frame.ok()) {
    disconnect("welcome was not received");
    return Status::failure(welcome_frame.error);
  }
  auto welcome_envelope = decode_frame(*welcome_frame);
  if (!welcome_envelope.ok()) return Status::failure(welcome_envelope.error);
  if (welcome_envelope->type != MessageType::Welcome) {
    return Status::failure(ErrorCode::MalformedInput, "federation did not answer with a welcome");
  }
  auto welcome = welcome_from_json(welcome_envelope->body);
  if (!welcome) return Status::failure(welcome.error);
  if (welcome->federation != config_.federation) {
    return Status::failure(ErrorCode::Divergent, "federation identity does not match");
  }

  SyncRequestMessage request_message;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    request_message.applied_global_generation = state_.applied_global_generation;
  }
  SequenceNumber sync_id{2};
  const Status sync_sent = socket_->send_frame(
      encode_frame(make_envelope(MessageType::SyncRequest, sync_id, sync_request_to_json(request_message))));
  if (!sync_sent.ok()) {
    disconnect("sync request could not be sent");
    return sync_sent;
  }
  auto response_frame = socket_->receive_frame(limits::kMaxWireMessageBytes);
  if (!response_frame.ok()) {
    disconnect("sync response was not received");
    return Status::failure(response_frame.error);
  }
  auto response_envelope = decode_frame(*response_frame);
  if (!response_envelope.ok()) return Status::failure(response_envelope.error);
  if (response_envelope->type != MessageType::SyncResponse) {
    return Status::failure(ErrorCode::MalformedInput, "federation did not answer with a sync response");
  }
  auto response = sync_response_from_json(response_envelope->body);
  if (!response) return Status::failure(response.error);
  if (!response->complete) {
    // A partial view is refused rather than applied: acting on half a policy is worse than
    // waiting for a complete one.
    return Status::failure(ErrorCode::Indeterminate,
                           "federation sent an explicitly partial sync response");
  }
  return ingest_sync(*response, now, accepted_count, rejected_count);
}

Status SiteRuntime::report_receipts(Timestamp now, std::size_t* reported) {
  std::vector<Receipt> batch;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (socket_ == nullptr) {
      return Status::failure(ErrorCode::NotConnected, "site is not connected to the federation");
    }
    const std::size_t limit = std::min(pending_receipts_.size(), limits::kMaxPendingReceipts);
    batch.assign(pending_receipts_.begin(), pending_receipts_.begin() + static_cast<std::ptrdiff_t>(limit));
  }
  if (batch.empty()) {
    if (reported != nullptr) *reported = 0;
    return Status::success();
  }
  ReceiptReportMessage report;
  report.receipts = batch;
  report.replay = true;  // receipts are re-reported until acknowledged; the federation deduplicates
  SequenceNumber id{3};
  const Status sent = socket_->send_frame(
      encode_frame(make_envelope(MessageType::ReceiptReport, id, receipt_report_to_json(report))));
  if (!sent.ok()) {
    disconnect("receipt report could not be sent");
    return sent;
  }
  auto ack_frame = socket_->receive_frame(limits::kMaxWireMessageBytes);
  if (!ack_frame.ok()) {
    disconnect("receipt acknowledgement was not received");
    return Status::failure(ack_frame.error);
  }
  auto ack_envelope = decode_frame(*ack_frame);
  if (!ack_envelope.ok()) return Status::failure(ack_envelope.error);
  if (ack_envelope->type != MessageType::Ack) {
    return Status::failure(ErrorCode::MalformedInput, "federation did not acknowledge the receipts");
  }
  auto ack = ack_from_json(ack_envelope->body);
  if (!ack) return Status::failure(ack.error);
  if (!ack->accepted) {
    return Status::failure(ErrorCode::Refused, "federation refused the receipts", ack->detail);
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::set<std::string> acknowledged = [&] {
      std::set<std::string> ids;
      const std::size_t count = std::min(batch.size(), static_cast<std::size_t>(ack->request_id.value));
      for (std::size_t i = 0; i < count; ++i) ids.insert(batch[i].id.to_string());
      return ids;
    }();
    pending_receipts_.erase(std::remove_if(pending_receipts_.begin(), pending_receipts_.end(),
                                           [&](const Receipt& receipt) {
                                             return acknowledged.count(receipt.id.to_string()) != 0;
                                           }),
                            pending_receipts_.end());
    status_.pending_receipts = pending_receipts_.size();
    status_.reported_receipts += acknowledged.size();
    last_contact_at_ = now;
  }
  emit(SiteEvent{SiteEventKind::ReceiptsReported, "reported", "receipts acknowledged", PolicyBundleId{},
                 OverrideId{}, Generation{}, batch.size()});
  if (reported != nullptr) *reported = batch.size();
  return Status::success();
}

void SiteRuntime::disconnect(const std::string& reason) {
  bool was_connected = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    was_connected = status_.connected;
    status_.connected = false;
    status_.partitioned = true;
  }
  if (socket_ != nullptr) {
    socket_->close();
    socket_.reset();
  }
  if (was_connected || !reason.empty()) {
    emit(SiteEvent{SiteEventKind::Disconnected, "disconnected", reason, PolicyBundleId{}, OverrideId{},
                   Generation{}, 1});
  }
}

bool SiteRuntime::is_connected() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return status_.connected;
}

SiteStatus SiteRuntime::status() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return status_;
}

PersistedSiteState SiteRuntime::state() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_;
}

AuthorityLedger SiteRuntime::ledger() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return ledger_;
}

const StoreIdentity& SiteRuntime::identity() const { return store_->identity(); }
// ---------------------------------------------------------------------------------------
// FederationRuntime
// ---------------------------------------------------------------------------------------

namespace {

Generation highest_generation(const std::vector<PolicyBundle>& bundles) {
  Generation highest{};
  for (const PolicyBundle& bundle : bundles) {
    if (bundle.global_generation > highest) highest = bundle.global_generation;
  }
  return highest;
}

}  // namespace

FederationRuntime::FederationRuntime() = default;

FederationRuntime::~FederationRuntime() {
  auto status = shutdown();
  (void)status;
}

Result<std::unique_ptr<FederationRuntime>> FederationRuntime::open(const FederationConfig& config) {
  if (config.federation.is_nil() || config.root_member.is_nil() || config.coordinator_site.is_nil()) {
    return Result<std::unique_ptr<FederationRuntime>>::failure(
        ErrorCode::InvalidArgument,
        "federation configuration needs federation, root member and coordinator site identities");
  }
  if (!net::is_valid_host(config.bind_address)) {
    return Result<std::unique_ptr<FederationRuntime>>::failure(ErrorCode::InvalidArgument,
                                                               "invalid bind address",
                                                               config.bind_address);
  }
  StoreOpenOptions options;
  options.directory = config.store_directory;
  options.identity.federation = config.federation;
  options.identity.member = config.root_member;
  options.identity.site = config.coordinator_site;
  options.identity.created_at = Timestamp{platform::system_now_millis()};
  IdGenerator generator(config.id_seed);
  options.identity.id.value = generator.next();
  auto store = DurableStore::open(options);
  if (!store.ok()) return Result<std::unique_ptr<FederationRuntime>>::failure(store.error);

  auto runtime = std::unique_ptr<FederationRuntime>(new FederationRuntime());
  runtime->config_ = config;
  runtime->store_ = std::make_unique<DurableStore>(std::move(*store.value));
  auto replayed = replay_records(runtime->store_->identity(), runtime->store_->records());
  if (!replayed) return Result<std::unique_ptr<FederationRuntime>>::failure(replayed.error);
  runtime->state_ = std::move(*replayed.value);
  runtime->state_.identity = runtime->store_->identity();
  runtime->ledger_.set_federation(config.federation);
  runtime->ledger_.set_root_member(config.root_member);
  const Timestamp now{platform::system_now_millis()};
  const Status restored = runtime->ledger_.restore(runtime->state_.grants, runtime->state_.revocations,
                                                   runtime->state_.authority_epoch, now);
  if (!restored.ok()) return Result<std::unique_ptr<FederationRuntime>>::failure(restored.error);
  if (runtime->state_.has_catalog) runtime->catalog_ = runtime->state_.catalog;

  auto listener = net::Socket::listen(config.bind_address, config.port);
  if (!listener.ok()) return Result<std::unique_ptr<FederationRuntime>>::failure(listener.error);
  runtime->listener_ = std::make_unique<net::Socket>(std::move(*listener.value));
  runtime->status_.listening = true;
  runtime->status_.global_generation = highest_generation(runtime->state_.accepted_bundles);
  runtime->status_.published_bundles = runtime->state_.accepted_bundles.size();
  runtime->status_.grants = runtime->state_.grants.size();
  runtime->status_.revocations = runtime->state_.revocations.size();
  runtime->status_.collected_receipts = runtime->state_.receipts.size();
  runtime->status_.catalog_generation = runtime->catalog_.generation.value;
  runtime->status_.authority_epoch = runtime->ledger_.epoch();
  return Result<std::unique_ptr<FederationRuntime>>::success(std::move(runtime));
}

Status FederationRuntime::append_record_locked(StoreRecordKind kind, std::string payload, Timestamp now) {
  const Status appended = store_->append(kind, payload, now);
  if (!appended.ok()) return appended;
  StoreRecord record;
  record.kind = kind;
  record.writer_epoch = store_->epoch();
  record.sequence = store_->last_sequence();
  record.payload = payload;
  record.payload_digest = Sha256::hash(payload);
  bool applied = false;
  return apply_record(state_, record, applied);
}

Status FederationRuntime::add_root_grant(const AuthorityGrant& grant, Timestamp now) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Status status = ledger_.add_root_grant(grant, now);
  if (!status.ok()) return status;
  const Status persisted = append_record_locked(StoreRecordKind::AuthorityGrantAdded,
                                                encode_grant_record(grant), now);
  if (!persisted.ok()) return persisted;
  status_.grants = state_.grants.size();
  status_.authority_epoch = ledger_.epoch();
  return Status::success();
}

Status FederationRuntime::add_grant(const AuthorityGrant& grant, Timestamp now,
                                    const MembershipBinding* membership) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Status status = ledger_.add_grant(grant, now, membership);
  if (!status.ok()) return status;
  const Status persisted = append_record_locked(StoreRecordKind::AuthorityGrantAdded,
                                                encode_grant_record(grant), now);
  if (!persisted.ok()) return persisted;
  status_.grants = state_.grants.size();
  return Status::success();
}

Status FederationRuntime::set_membership(MembershipBinding membership) {
  const Status validity = validate_membership_binding(membership);
  if (!validity.ok()) return validity;
  std::lock_guard<std::mutex> lock(mutex_);
  membership_ = std::move(membership);
  return Status::success();
}

Status FederationRuntime::set_catalog(const CapabilityCatalog& catalog, Timestamp now) {
  const Status validity = validate_capability_catalog(catalog);
  if (!validity.ok()) return validity;
  std::lock_guard<std::mutex> lock(mutex_);
  if (state_.has_catalog && state_.catalog.generation == catalog.generation &&
      state_.catalog.capabilities.size() == catalog.capabilities.size()) {
    // Re-declaring the same catalog is a no-op instead of another journal record.
    catalog_ = catalog;
    return Status::success();
  }
  catalog_ = catalog;
  const Status persisted = append_record_locked(StoreRecordKind::CapabilityCatalogUpdated,
                                                encode_catalog_record(catalog), now);
  if (!persisted.ok()) return persisted;
  status_.catalog_generation = catalog.generation.value;
  return Status::success();
}

Status FederationRuntime::publish_bundle(PolicyBundle bundle, Timestamp now, std::string* reason_code) {
  if (bundle.federation.is_nil()) bundle.federation = config_.federation;
  if (bundle.federation != config_.federation) {
    set_reason(reason_code, "wrong-federation");
    return Status::failure(ErrorCode::InvalidArgument, "bundle belongs to another federation");
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (state_.accepted_bundles.size() >= limits::kMaxBundlesPerFederation) {
    return Status::failure(ErrorCode::TooLarge, "federation holds too many published bundles");
  }
  // Rights are checked per rule class, because publishing binding policy is a different right
  // from publishing a default.
  bool has_mandatory = false;
  bool has_other = false;
  std::vector<std::string> domains;
  for (const Rule& rule : bundle.rules) {
    if (rule.rule_class == RuleClass::Mandatory) {
      has_mandatory = true;
    } else {
      has_other = true;
    }
    if (std::find(domains.begin(), domains.end(), rule.domain) == domains.end()) {
      domains.push_back(rule.domain);
    }
  }
  const std::string single_domain = domains.size() == 1 ? domains.front() : std::string();
  if (bundle.rules.empty()) has_other = true;
  if (has_mandatory) {
    const AuthorityDecision decision = ledger_.evaluate(bundle.issuer_member,
                                                        AuthorityAction::PublishMandatory, bundle.scope,
                                                        single_domain, now, &membership_);
    if (!decision.granted()) {
      set_reason(reason_code, std::string("publish-mandatory:") + authority_outcome_name(decision.outcome));
      return Status::failure(ErrorCode::Unauthorized, "issuer holds no mandatory publication authority",
                             decision.detail);
    }
  }
  if (has_other) {
    const AuthorityDecision decision = ledger_.evaluate(bundle.issuer_member,
                                                        AuthorityAction::PublishPolicy, bundle.scope,
                                                        single_domain, now, &membership_);
    if (!decision.granted()) {
      set_reason(reason_code, std::string("publish-policy:") + authority_outcome_name(decision.outcome));
      return Status::failure(ErrorCode::Unauthorized, "issuer holds no publication authority",
                             decision.detail);
    }
  }

  // Re-applying the same plan must not publish the same bundle twice: identity plus content
  // decides, so an unchanged publication is a no-op and a changed one is refused rather than
  // silently re-versioned.
  auto content = compute_bundle_content_digest(bundle);
  if (!content) return Status::failure(content.error);
  for (const PolicyBundle& existing : state_.accepted_bundles) {
    if (!(existing.id == bundle.id)) continue;
    auto existing_content = compute_bundle_content_digest(existing);
    if (!existing_content) return Status::failure(existing_content.error);
    if (*existing_content == *content) {
      set_reason(reason_code, "already-published");
      return Status::success();
    }
    set_reason(reason_code, "divergent-content");
    return Status::failure(ErrorCode::Divergent,
                           "the same bundle identity was published with different content",
                           bundle.id.to_string());
  }

  // Generations are per publisher and scope: a publisher cannot skip ahead of its own history and
  // cannot reuse a generation it already published.
  Generation next{1};
  for (const PolicyBundle& existing : state_.accepted_bundles) {
    if (existing.issuer_member != bundle.issuer_member) continue;
    if (!(existing.scope == bundle.scope)) continue;
    auto following = existing.global_generation.next();
    if (!following) return Status::failure(following.error);
    if (*following > next) next = *following;
  }
  bundle.global_generation = next;
  const Status sealed = seal_bundle(bundle);
  if (!sealed.ok()) return sealed;
  const Status verified = verify_bundle(bundle);
  if (!verified.ok()) return verified;
  const Status persisted = append_record_locked(StoreRecordKind::BundleAccepted,
                                                encode_bundle_record(bundle), now);
  if (!persisted.ok()) return persisted;
  status_.published_bundles = state_.accepted_bundles.size();
  if (bundle.global_generation > status_.global_generation) {
    status_.global_generation = bundle.global_generation;
  }
  set_reason(reason_code, "published");
  return Status::success();
}

Status FederationRuntime::revoke(RevocationRecord record, Timestamp now,
                                 const MembershipBinding* membership) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (record.federation.is_nil()) record.federation = config_.federation;
  const Status status = ledger_.add_revocation(record, now, membership);
  if (!status.ok()) return status;
  const Status persisted = append_record_locked(StoreRecordKind::RevocationApplied,
                                                encode_revocation_record(record), now);
  if (!persisted.ok()) return persisted;
  status_.revocations = state_.revocations.size();
  return Status::success();
}

SyncResponseMessage FederationRuntime::build_sync_response_locked(const SyncRequestMessage& request) const {
  SyncResponseMessage response;
  response.current_generation = highest_generation(state_.accepted_bundles);
  response.has_catalog = true;
  response.catalog = catalog_;
  response.revocations = state_.revocations;
  response.grants = state_.grants;
  std::size_t sent = 0;
  for (const PolicyBundle& bundle : state_.accepted_bundles) {
    if (!request.applied_global_generation.is_nil() &&
        bundle.global_generation <= request.applied_global_generation) {
      continue;
    }
    if (sent >= limits::kMaxReconnectSyncRules) {
      // The answer is marked incomplete rather than silently truncated, so the site can tell the
      // difference between "nothing new" and "more to come".
      response.complete = false;
      break;
    }
    response.bundles.push_back(bundle);
    ++sent;
  }
  return response;
}

Status FederationRuntime::handle_session(net::Socket& socket, Timestamp now) {
  SequenceNumber reply_id{1};
  while (!stopping_) {
    auto frame = socket.receive_frame(limits::kMaxWireMessageBytes);
    if (!frame.ok()) {
      // A closed peer is the normal end of a session and is not an error.
      return Status::success();
    }
    auto envelope = decode_frame(*frame);
    if (!envelope.ok()) {
      ErrorMessage error;
      error.code = error_code_name(envelope.error.code);
      error.detail = envelope.error.message;
      const Status sent = socket.send_frame(encode_frame(
          make_envelope(MessageType::ErrorReport, reply_id, error_to_json(error))));
      if (!sent.ok()) return sent;
      continue;
    }
    switch (envelope->type) {
      case MessageType::Hello: {
        auto hello = hello_from_json(envelope->body);
        if (!hello) {
          ErrorMessage error;
          error.code = error_code_name(hello.error.code);
          error.detail = hello.error.message;
          const Status sent = socket.send_frame(encode_frame(
              make_envelope(MessageType::ErrorReport, reply_id, error_to_json(error))));
          if (!sent.ok()) return sent;
          break;
        }
        if (hello->federation != config_.federation) {
          ErrorMessage error;
          error.code = "wrong-federation";
          error.detail = "hello names a different federation";
          const Status sent = socket.send_frame(encode_frame(
              make_envelope(MessageType::ErrorReport, reply_id, error_to_json(error))));
          if (!sent.ok()) return sent;
          break;
        }
        WelcomeMessage welcome;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          welcome.federation = config_.federation;
          welcome.authority_epoch = ledger_.epoch();
          welcome.global_generation = highest_generation(state_.accepted_bundles);
          welcome.session = reply_id;
          welcome.has_catalog = true;
          welcome.catalog = catalog_;
        }
        // The handshake answers the handshake. Policy always travels in reply to an explicit sync
        // request, so a site never has to guess how many frames to expect.
        const Status sent = socket.send_frame(encode_frame(
            make_envelope(MessageType::Welcome, reply_id, welcome_to_json(welcome))));
        if (!sent.ok()) return sent;
        break;
      }
      case MessageType::SyncRequest: {
        auto request = sync_request_from_json(envelope->body);
        if (!request) return Status::failure(request.error);
        SyncResponseMessage response;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          response = build_sync_response_locked(*request);
        }
        const Status sent = socket.send_frame(
            encode_frame(make_envelope(MessageType::SyncResponse, reply_id, sync_response_to_json(response))));
        if (!sent.ok()) return sent;
        break;
      }
      case MessageType::ReceiptReport: {
        auto report = receipt_report_from_json(envelope->body);
        if (!report) return Status::failure(report.error);
        std::size_t recorded = 0;
        {
          std::lock_guard<std::mutex> lock(mutex_);
          for (const Receipt& receipt : report->receipts) {
            const Status validity = validate_receipt(receipt);
            if (!validity.ok()) {
              ++status_.rejected_receipts;
              continue;
            }
            bool present = false;
            for (const Receipt& existing : state_.receipts) {
              if (existing.id == receipt.id) {
                present = true;
                break;
              }
            }
            if (present) {
              // Already recorded: deduplication by receipt identity is what makes re-reporting
              // after a partition safe.
              ++recorded;
              continue;
            }
            if (state_.receipts.size() >= limits::kMaxReceiptsPerSite) {
              ++status_.rejected_receipts;
              continue;
            }
            Receipt stored = receipt;
            stored.sequence = state_.next_receipt_sequence;
            auto following = state_.next_receipt_sequence.next();
            if (!following) return Status::failure(following.error);
            const Status sealed = seal_receipt(stored);
            if (!sealed.ok()) return sealed;
            const std::string payload = encode_receipt_record(stored);
            const Status appended = store_->append(StoreRecordKind::ReceiptAppended, payload, now);
            if (!appended.ok()) return appended;
            StoreRecord record;
            record.kind = StoreRecordKind::ReceiptAppended;
            record.writer_epoch = store_->epoch();
            record.sequence = store_->last_sequence();
            record.payload = payload;
            record.payload_digest = Sha256::hash(payload);
            bool applied = false;
            const Status status = apply_record(state_, record, applied);
            if (!status.ok()) return status;
            state_.next_receipt_sequence = *following;
            ++recorded;
          }
          status_.collected_receipts = state_.receipts.size();
        }
        AckMessage ack;
        ack.request_id = SequenceNumber{recorded};
        ack.reason_code = "receipts-recorded";
        ack.detail = "receipts accepted and journaled";
        ack.accepted = true;
        const Status sent = socket.send_frame(encode_frame(make_ack(reply_id, envelope->id, ack)));
        if (!sent.ok()) return sent;
        break;
      }
      case MessageType::OverrideReport: {
        auto report = override_report_from_json(envelope->body);
        if (!report) return Status::failure(report.error);
        {
          std::lock_guard<std::mutex> lock(mutex_);
          if (state_.receipts.size() < limits::kMaxReceiptsPerSite) {
            Receipt receipt;
            receipt.federation = report->override_record.federation;
            receipt.member = report->override_record.member;
            receipt.site = report->override_record.site;
            receipt.bundle = report->override_record.target_bundle;
            receipt.global_generation = report->override_record.target_bundle_generation;
            receipt.local_generation = report->override_record.local_generation;
            receipt.kind = ReceiptKind::Overridden;
            receipt.reason_code = report->outcome_code.empty() ? "override-reported" : report->outcome_code;
            receipt.detail = report->outcome_detail;
            receipt.rule = report->override_record.target_rule;
            receipt.rule_digest = report->override_record.target_rule_digest;
            receipt.bundle_digest = report->override_record.target_bundle_digest;
            receipt.override_id = report->override_record.id;
            receipt.at = report->override_record.created_at;
            receipt.sequence = state_.next_receipt_sequence;
            auto following = state_.next_receipt_sequence.next();
            if (!following) return Status::failure(following.error);
            const Status sealed = seal_receipt(receipt);
            if (!sealed.ok()) return sealed;
            const std::string payload = encode_receipt_record(receipt);
            const Status appended = store_->append(StoreRecordKind::ReceiptAppended, payload, now);
            if (!appended.ok()) return appended;
            StoreRecord record;
            record.kind = StoreRecordKind::ReceiptAppended;
            record.writer_epoch = store_->epoch();
            record.sequence = store_->last_sequence();
            record.payload = payload;
            record.payload_digest = Sha256::hash(payload);
            bool applied = false;
            const Status status = apply_record(state_, record, applied);
            if (!status.ok()) return status;
            state_.next_receipt_sequence = *following;
            status_.collected_receipts = state_.receipts.size();
          }
        }
        AckMessage ack;
        ack.request_id = envelope->id;
        ack.reason_code = "override-recorded";
        ack.detail = "override report journaled";
        const Status sent = socket.send_frame(encode_frame(make_ack(reply_id, envelope->id, ack)));
        if (!sent.ok()) return sent;
        break;
      }
      case MessageType::Shutdown: {
        return Status::success();
      }
      case MessageType::ErrorReport:
      case MessageType::Ack:
      case MessageType::Welcome:
      case MessageType::SyncResponse:
      case MessageType::PolicyUpdate: {
        // Peers do not send these to the coordinator; ignoring them is safer than guessing.
        break;
      }
    }
  }
  return Status::success();
}

Status FederationRuntime::serve_once(Timestamp now) {
  if (listener_ == nullptr) {
    return Status::failure(ErrorCode::InvalidState, "federation is not listening");
  }
  auto accepted = listener_->accept();
  if (!accepted.ok()) {
    if (stopping_) return Status::failure(ErrorCode::Cancelled, "federation is stopping");
    return Status::failure(accepted.error);
  }
  net::Socket session = std::move(*accepted.value);
  const Status status = handle_session(session, now);
  session.close();
  {
    std::lock_guard<std::mutex> lock(mutex_);
    ++status_.sessions;
  }
  return status;
}

void FederationRuntime::stop() {
  stopping_ = true;
  status_.stopping = true;
  // Closing the listener is what unblocks a pending accept; no clock or watchdog is involved.
  if (listener_ != nullptr) listener_->close();
}

Status FederationRuntime::shutdown() {
  stop();
  if (store_ != nullptr) {
    const Status status = store_->close();
    if (!status.ok()) return status;
  }
  status_.listening = false;
  return Status::success();
}

FederationStatus FederationRuntime::status() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return status_;
}

std::vector<PolicyBundle> FederationRuntime::bundles() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_.accepted_bundles;
}

AuthorityLedger FederationRuntime::ledger() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return ledger_;
}

std::vector<Receipt> FederationRuntime::collected_receipts() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_.receipts;
}

CapabilityCatalog FederationRuntime::catalog() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return catalog_;
}

std::uint16_t FederationRuntime::port() const {
  return listener_ != nullptr ? listener_->local_port() : 0;
}

}  // namespace gpf
