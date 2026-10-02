#include "gpf/authority.hpp"

#include <algorithm>
#include <set>

namespace gpf {
namespace {

Status invalid(std::string message, std::string detail = {}) {
  return Status::failure(ErrorCode::InvalidArgument, std::move(message), std::move(detail));
}

void write_scope(CanonicalWriter& writer, const RuleScope& scope) {
  writer.u8(static_cast<std::uint8_t>(scope.level));
  writer.u64(static_cast<std::uint64_t>(scope.members.size()));
  for (MemberId id : scope.members) writer.id(id.value);
  writer.u64(static_cast<std::uint64_t>(scope.sites.size()));
  for (SiteId id : scope.sites) writer.id(id.value);
}

// Failure precedence used when several candidate grants each fail. Reporting the most
// consequential reason keeps revocation and expiry visible instead of masking them behind a
// generic scope mismatch. It never turns a failure into a success.
int outcome_priority(AuthorityOutcome outcome) {
  switch (outcome) {
    case AuthorityOutcome::Revoked: return 7;
    case AuthorityOutcome::Expired: return 6;
    case AuthorityOutcome::NotYetValid: return 5;
    case AuthorityOutcome::EpochFenced: return 4;
    case AuthorityOutcome::BrokenChain: return 3;
    case AuthorityOutcome::DomainNotCovered: return 2;
    case AuthorityOutcome::OutOfScope: return 1;
    case AuthorityOutcome::Granted: return 0;
    case AuthorityOutcome::NoGrant: return 0;
  }
  return 0;
}

}  // namespace

const char* authority_action_name(AuthorityAction value) noexcept {
  switch (value) {
    case AuthorityAction::Delegate: return "delegate";
    case AuthorityAction::PublishPolicy: return "publish-policy";
    case AuthorityAction::PublishMandatory: return "publish-mandatory";
    case AuthorityAction::Revoke: return "revoke";
    case AuthorityAction::OverridePolicy: return "override-policy";
  }
  return "unknown";
}

Result<AuthorityAction> authority_action_from_name(std::string_view name) {
  if (name == "delegate") return Result<AuthorityAction>::success(AuthorityAction::Delegate);
  if (name == "publish-policy") return Result<AuthorityAction>::success(AuthorityAction::PublishPolicy);
  if (name == "publish-mandatory") return Result<AuthorityAction>::success(AuthorityAction::PublishMandatory);
  if (name == "revoke") return Result<AuthorityAction>::success(AuthorityAction::Revoke);
  if (name == "override-policy") return Result<AuthorityAction>::success(AuthorityAction::OverridePolicy);
  return Result<AuthorityAction>::failure(ErrorCode::MalformedInput, "unknown authority action",
                                          escape_preview(name));
}

const char* revocation_target_name(RevocationTarget value) noexcept {
  switch (value) {
    case RevocationTarget::Grant: return "grant";
    case RevocationTarget::Bundle: return "bundle";
    case RevocationTarget::Rule: return "rule";
  }
  return "unknown";
}

Result<RevocationTarget> revocation_target_from_name(std::string_view name) {
  if (name == "grant") return Result<RevocationTarget>::success(RevocationTarget::Grant);
  if (name == "bundle") return Result<RevocationTarget>::success(RevocationTarget::Bundle);
  if (name == "rule") return Result<RevocationTarget>::success(RevocationTarget::Rule);
  return Result<RevocationTarget>::failure(ErrorCode::MalformedInput, "unknown revocation target",
                                           escape_preview(name));
}

const char* authority_outcome_name(AuthorityOutcome value) noexcept {
  switch (value) {
    case AuthorityOutcome::Granted: return "granted";
    case AuthorityOutcome::NoGrant: return "no-grant";
    case AuthorityOutcome::OutOfScope: return "out-of-scope";
    case AuthorityOutcome::DomainNotCovered: return "domain-not-covered";
    case AuthorityOutcome::NotYetValid: return "not-yet-valid";
    case AuthorityOutcome::Expired: return "expired";
    case AuthorityOutcome::Revoked: return "revoked";
    case AuthorityOutcome::BrokenChain: return "broken-chain";
    case AuthorityOutcome::EpochFenced: return "epoch-fenced";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------------------

bool AuthorityGrant::covers_domain(std::string_view domain) const noexcept {
  if (conflict_domains.empty()) return true;
  for (const std::string& entry : conflict_domains) {
    if (entry == domain) return true;
  }
  return false;
}

bool AuthorityGrant::is_time_valid_at(Timestamp now) const noexcept {
  if (now.ms < not_before.ms) return false;
  if (not_after.ms != 0 && now.ms >= not_after.ms) return false;
  return true;
}

Status validate_grant(const AuthorityGrant& grant) {
  if (grant.id.is_nil()) return invalid("grant identity is nil");
  if (grant.federation.is_nil()) return invalid("grant federation is nil");
  if (grant.grantor.is_nil()) return invalid("grant grantor is nil");
  if (grant.grantee.is_nil()) return invalid("grant grantee is nil");
  auto scope_status = validate_scope(grant.scope);
  if (!scope_status.ok()) return scope_status;
  if (grant.conflict_domains.size() > 256) {
    return Status::failure(ErrorCode::TooLarge, "grant lists too many conflict domains", {});
  }
  std::set<std::string> seen;
  for (const std::string& domain : grant.conflict_domains) {
    if (!is_valid_identifier(domain)) {
      return invalid("grant names an invalid conflict domain", escape_preview(domain));
    }
    if (!seen.insert(domain).second) return invalid("grant repeats a conflict domain", domain);
  }
  if (grant.not_after.ms != 0 && grant.not_after.ms <= grant.not_before.ms) {
    return invalid("grant expires at or before it becomes valid", grant.id.to_string());
  }
  if (!is_valid_utf8(grant.justification) || grant.justification.size() > limits::kMaxRationaleLength) {
    return invalid("grant justification is invalid or too long", grant.id.to_string());
  }
  return Status::success();
}

Result<Digest> compute_grant_digest(const AuthorityGrant& grant) {
  CanonicalWriter writer;
  writer.tag("gpf.grant.v1");
  writer.id(grant.id.value);
  writer.id(grant.federation.value);
  writer.id(grant.grantor.value);
  writer.id(grant.grantee.value);
  writer.id(grant.parent.value);
  writer.u8(static_cast<std::uint8_t>(grant.action));
  write_scope(writer, grant.scope);
  std::vector<std::string> domains = grant.conflict_domains;
  std::sort(domains.begin(), domains.end());
  domains.erase(std::unique(domains.begin(), domains.end()), domains.end());
  writer.u64(static_cast<std::uint64_t>(domains.size()));
  for (const std::string& domain : domains) writer.str(domain);
  writer.i64(grant.not_before.ms);
  writer.i64(grant.not_after.ms);
  writer.u64(grant.authority_epoch.value);
  writer.str(grant.justification);
  return Result<Digest>::success(writer.digest());
}

Status seal_grant(AuthorityGrant& grant) {
  auto digest = compute_grant_digest(grant);
  if (!digest) return Status::failure(digest.error);
  grant.digest = *digest;
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------------------

GrantId RevocationRecord::target_grant() const {
  GrantId out;
  if (target == RevocationTarget::Grant) out.value = target_id;
  return out;
}

PolicyBundleId RevocationRecord::target_bundle() const {
  PolicyBundleId out;
  if (target == RevocationTarget::Bundle) out.value = target_id;
  return out;
}

RuleId RevocationRecord::target_rule() const {
  RuleId out;
  if (target == RevocationTarget::Rule) out.value = target_id;
  return out;
}

Status validate_revocation(const RevocationRecord& record) {
  if (record.id.is_nil()) return invalid("revocation identity is nil");
  if (record.federation.is_nil()) return invalid("revocation federation is nil");
  if (record.target_id.is_nil()) return invalid("revocation names no target");
  if (record.actor.empty() || record.actor.size() > limits::kMaxShortTextLength ||
      !is_valid_utf8(record.actor)) {
    return invalid("revocation must be attributable to an actor");
  }
  if (record.actor_member.is_nil()) return invalid("revocation has no acting member");
  if (record.sequence.is_nil()) return invalid("revocation sequence is nil");
  if (!is_valid_utf8(record.reason) || record.reason.empty() ||
      record.reason.size() > kMaxOverrideReasonLength) {
    return invalid("revocation must state a bounded reason");
  }
  if (record.effective_at.ms < record.issued_at.ms) {
    return invalid("revocation takes effect before it was issued");
  }
  return Status::success();
}

Result<Digest> compute_revocation_digest(const RevocationRecord& record) {
  CanonicalWriter writer;
  writer.tag("gpf.revocation.v1");
  writer.id(record.id.value);
  writer.id(record.federation.value);
  writer.u8(static_cast<std::uint8_t>(record.target));
  writer.id(record.target_id);
  writer.id(record.actor_member.value);
  writer.str(record.actor);
  writer.id(record.authority.value);
  writer.u64(record.authority_epoch.value);
  writer.u64(record.sequence.value);
  writer.i64(record.issued_at.ms);
  writer.i64(record.effective_at.ms);
  writer.str(record.reason);
  return Result<Digest>::success(writer.digest());
}

Status seal_revocation(RevocationRecord& record) {
  auto digest = compute_revocation_digest(record);
  if (!digest) return Status::failure(digest.error);
  record.digest = *digest;
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------------------

AuthorityLedger::AuthorityLedger(FederationId federation) : federation_(federation) {}

Result<Epoch> AuthorityLedger::advance_epoch(Timestamp) {
  auto next = epoch_.next();
  if (!next) return next;
  epoch_ = *next;
  return Result<Epoch>::success(epoch_);
}

const AuthorityGrant* AuthorityLedger::find_grant(GrantId id) const noexcept {
  for (const AuthorityGrant& grant : grants_) {
    if (grant.id == id) return &grant;
  }
  return nullptr;
}

void AuthorityLedger::index_grant(const AuthorityGrant& grant) { grants_.push_back(grant); }

void AuthorityLedger::index_revocation(const RevocationRecord& record) {
  revocations_.push_back(record);
  if (record.sequence > last_revocation_sequence_) last_revocation_sequence_ = record.sequence;
  switch (record.target) {
    case RevocationTarget::Grant: {
      GrantId id;
      id.value = record.target_id;
      revoked_grants_.push_back(id);
      break;
    }
    case RevocationTarget::Bundle: {
      PolicyBundleId id;
      id.value = record.target_id;
      revoked_bundles_.push_back(id);
      break;
    }
    case RevocationTarget::Rule: {
      RuleId id;
      id.value = record.target_id;
      revoked_rules_.push_back(id);
      break;
    }
  }
}

Status AuthorityLedger::add_root_grant(const AuthorityGrant& grant, Timestamp now) {
  auto status = validate_grant(grant);
  if (!status.ok()) return status;
  if (!grant.parent.is_nil()) return invalid("root grant must not name a parent grant");
  if (grant.action != AuthorityAction::Delegate) {
    return invalid("root grant must carry the delegate action");
  }
  if (!root_grant_.is_nil()) {
    const AuthorityGrant* existing = find_grant(root_grant_);
    const bool existing_is_current = existing != nullptr && existing->authority_epoch == epoch_;
    if (existing_is_current) {
      // Applying the same plan again is idempotent: the identical root grant is already in force.
      if (existing->id == grant.id) {
        auto computed = compute_grant_digest(grant);
        if (computed && *computed == existing->digest) return Status::success();
      }
      return Status::failure(ErrorCode::AlreadyExists,
                             "federation root grant already exists for the current authority epoch",
                             root_grant_.to_string());
    }
    // The epoch has moved on, so the previous root authority is fenced. Re-establishing the root
    // is the deliberate recovery path after a compromise, and it is recorded like any other
    // grant: the old root stays in the ledger as fenced history rather than being erased.
  }
  if (root_member_.is_nil() || grant.grantor != root_member_) {
    return Status::failure(ErrorCode::Unauthorized,
                           "root grant must be issued by the configured federation root member",
                           grant.grantor.to_string());
  }
  if (now.ms < grant.not_before.ms) return invalid("root grant is not yet valid");
  if (grant.not_after.ms != 0 && now.ms >= grant.not_after.ms) return invalid("root grant is already expired");
  if (!grant.digest.is_zero()) {
    auto computed = compute_grant_digest(grant);
    if (!computed) return Status::failure(computed.error);
    if (*computed != grant.digest) {
      return Status::failure(ErrorCode::IntegrityFailure, "root grant digest does not match content",
                             grant.id.to_string());
    }
  }
  AuthorityGrant stored = grant;
  if (stored.authority_epoch.value == 0) stored.authority_epoch = epoch_;
  if (stored.authority_epoch != epoch_) {
    return Status::failure(ErrorCode::EpochFenced, "root grant belongs to a superseded authority epoch",
                           grant.id.to_string());
  }
  auto sealed = seal_grant(stored);
  if (!sealed.ok()) return sealed;
  index_grant(stored);
  root_grant_ = stored.id;
  return Status::success();
}

Status AuthorityLedger::add_grant(const AuthorityGrant& grant, Timestamp now,
                                  const MembershipBinding* membership) {
  auto status = validate_grant(grant);
  if (!status.ok()) return status;
  if (grant.parent.is_nil()) {
    return invalid("use add_root_grant to bootstrap the federation root grant",
                   grant.id.to_string());
  }
  if (const AuthorityGrant* existing = find_grant(grant.id)) {
    // Idempotent re-application of the same delegation; a different grant under the same identity
    // is a conflict rather than a replacement.
    auto computed = compute_grant_digest(grant);
    if (computed && *computed == existing->digest) return Status::success();
    return Status::failure(ErrorCode::AlreadyExists, "grant identity already exists",
                           grant.id.to_string());
  }
  const AuthorityGrant* parent = find_grant(grant.parent);
  if (parent == nullptr) {
    return Status::failure(ErrorCode::NotFound, "parent grant is unknown", grant.parent.to_string());
  }
  if (parent->action != AuthorityAction::Delegate) {
    return Status::failure(ErrorCode::Unauthorized, "parent grant does not permit delegation",
                           parent->id.to_string());
  }
  if (grant.grantor != parent->grantee) {
    return Status::failure(ErrorCode::Unauthorized,
                           "grant grantor does not hold the parent grant", grant.grantor.to_string());
  }
  if (!scope_contains_scope(parent->scope, grant.scope, membership)) {
    return Status::failure(ErrorCode::Forbidden, "grant widens the parent grant scope",
                           grant.id.to_string());
  }
  if (!parent->conflict_domains.empty()) {
    if (grant.conflict_domains.empty()) {
      return Status::failure(ErrorCode::Forbidden,
                             "grant must narrow the parent conflict domain list",
                             grant.id.to_string());
    }
    for (const std::string& domain : grant.conflict_domains) {
      if (!parent->covers_domain(domain)) {
        return Status::failure(ErrorCode::Forbidden, "grant widens the parent conflict domains",
                               domain);
      }
    }
  }
  auto parent_chain = verify_chain(parent->id, now, membership);
  if (!parent_chain.granted()) {
    return Status::failure(ErrorCode::Unauthorized, "parent grant chain is not valid",
                           std::string(authority_outcome_name(parent_chain.outcome)));
  }
  AuthorityGrant stored = grant;
  if (stored.authority_epoch.value == 0) stored.authority_epoch = epoch_;
  if (stored.authority_epoch != epoch_) {
    return Status::failure(ErrorCode::EpochFenced, "grant belongs to a superseded authority epoch",
                           grant.id.to_string());
  }
  if (!grant.digest.is_zero()) {
    auto computed = compute_grant_digest(grant);
    if (!computed) return Status::failure(computed.error);
    if (*computed != grant.digest) {
      return Status::failure(ErrorCode::IntegrityFailure, "grant digest does not match content",
                             grant.id.to_string());
    }
  }
  auto sealed = seal_grant(stored);
  if (!sealed.ok()) return sealed;
  index_grant(stored);
  return Status::success();
}

Status AuthorityLedger::add_revocation(const RevocationRecord& record, Timestamp now,
                                       const MembershipBinding* membership) {
  auto status = validate_revocation(record);
  if (!status.ok()) return status;
  if (record.federation != federation_) {
    return invalid("revocation belongs to another federation", record.federation.to_string());
  }
  if (!record.digest.is_zero()) {
    auto computed = compute_revocation_digest(record);
    if (!computed) return Status::failure(computed.error);
    if (*computed != record.digest) {
      return Status::failure(ErrorCode::IntegrityFailure, "revocation digest does not match content",
                             record.id.to_string());
    }
  }
  // Revocation order is total and monotonic: replayed or reordered revocations are refused
  // instead of applied twice.
  if (record.sequence <= last_revocation_sequence_ && !last_revocation_sequence_.is_nil()) {
    return Status::failure(ErrorCode::Reordered, "revocation sequence is not increasing",
                           std::to_string(record.sequence.value));
  }
  // Authority for the revocation itself.
  if (record.authority.is_nil()) {
    if (record.actor_member != root_member_) {
      return Status::failure(ErrorCode::Unauthorized,
                             "only the federation root member may revoke without a delegation",
                             record.actor_member.to_string());
    }
  } else {
    auto chain = verify_chain(record.authority, now);
    if (!chain.granted()) {
      return Status::failure(ErrorCode::Unauthorized, "revocation authority is not valid",
                             std::string(authority_outcome_name(chain.outcome)));
    }
    const AuthorityGrant* authority = find_grant(record.authority);
    if (authority == nullptr || authority->action != AuthorityAction::Revoke) {
      return Status::failure(ErrorCode::Unauthorized, "revocation authority lacks the revoke action",
                             record.authority.to_string());
    }
    if (authority->grantee != record.actor_member) {
      return Status::failure(ErrorCode::Unauthorized,
                             "revocation actor does not hold the revocation authority",
                             record.actor_member.to_string());
    }
    if (record.target == RevocationTarget::Grant) {
      GrantId target;
      target.value = record.target_id;
      const AuthorityGrant* target_grant = find_grant(target);
      if (target_grant != nullptr &&
          !scope_contains_scope(authority->scope, target_grant->scope, membership)) {
        return Status::failure(ErrorCode::Forbidden, "revocation authority does not cover the target scope",
                               target.to_string());
      }
    }
  }
  RevocationRecord stored = record;
  if (stored.authority_epoch.value == 0) stored.authority_epoch = epoch_;
  auto sealed = seal_revocation(stored);
  if (!sealed.ok()) return sealed;
  index_revocation(stored);
  return Status::success();
}

bool AuthorityLedger::is_grant_revoked(GrantId id, Timestamp now) const noexcept {
  for (const RevocationRecord& record : revocations_) {
    if (record.target != RevocationTarget::Grant) continue;
    if (record.target_id != id.value) continue;
    if (record.is_effective_at(now)) return true;
  }
  return false;
}

bool AuthorityLedger::is_bundle_revoked(PolicyBundleId id, Timestamp now) const noexcept {
  for (const RevocationRecord& record : revocations_) {
    if (record.target != RevocationTarget::Bundle) continue;
    if (record.target_id != id.value) continue;
    if (record.is_effective_at(now)) return true;
  }
  return false;
}

bool AuthorityLedger::is_rule_revoked(RuleId id, Timestamp now) const noexcept {
  for (const RevocationRecord& record : revocations_) {
    if (record.target != RevocationTarget::Rule) continue;
    if (record.target_id != id.value) continue;
    if (record.is_effective_at(now)) return true;
  }
  return false;
}

const RevocationRecord* AuthorityLedger::find_revocation_for_grant(GrantId id) const noexcept {
  for (const RevocationRecord& record : revocations_) {
    if (record.target == RevocationTarget::Grant && record.target_id == id.value) return &record;
  }
  return nullptr;
}

AuthorityDecision AuthorityLedger::verify_chain(GrantId id, Timestamp now,
                                                 const MembershipBinding* membership) const {
  AuthorityDecision decision;
  decision.grant = id;
  const AuthorityGrant* current = find_grant(id);
  if (current == nullptr) {
    decision.outcome = AuthorityOutcome::NoGrant;
    decision.detail = "grant is not present in the ledger";
    return decision;
  }
  std::set<std::string> visited;
  while (true) {
    if (!visited.insert(current->id.to_string()).second) {
      decision.outcome = AuthorityOutcome::BrokenChain;
      decision.detail = "grant chain contains a cycle";
      return decision;
    }
    if (is_grant_revoked(current->id, now)) {
      decision.outcome = AuthorityOutcome::Revoked;
      decision.detail = "grant is revoked";
      decision.grant = current->id;
      return decision;
    }
    if (now.ms < current->not_before.ms) {
      decision.outcome = AuthorityOutcome::NotYetValid;
      decision.detail = "grant is not yet valid";
      decision.grant = current->id;
      return decision;
    }
    if (current->not_after.ms != 0 && now.ms >= current->not_after.ms) {
      decision.outcome = AuthorityOutcome::Expired;
      decision.detail = "grant has expired";
      decision.grant = current->id;
      return decision;
    }
    if (current->authority_epoch != epoch_) {
      decision.outcome = AuthorityOutcome::EpochFenced;
      decision.detail = "grant was issued under a superseded authority epoch";
      decision.grant = current->id;
      return decision;
    }
    if (current->parent.is_nil()) {
      if (current->id != root_grant_) {
        decision.outcome = AuthorityOutcome::BrokenChain;
        decision.detail = "grant chain does not reach the federation root grant";
        decision.grant = current->id;
        return decision;
      }
      decision.outcome = AuthorityOutcome::Granted;
      decision.detail = "chain verified to the federation root grant";
      decision.grant = id;
      return decision;
    }
    const AuthorityGrant* parent = find_grant(current->parent);
    if (parent == nullptr) {
      decision.outcome = AuthorityOutcome::BrokenChain;
      decision.detail = "parent grant is missing from the ledger";
      decision.grant = current->id;
      return decision;
    }
    if (parent->action != AuthorityAction::Delegate) {
      decision.outcome = AuthorityOutcome::BrokenChain;
      decision.detail = "parent grant does not permit delegation";
      decision.grant = current->id;
      return decision;
    }
    if (!scope_contains_scope(parent->scope, current->scope, membership)) {
      decision.outcome = AuthorityOutcome::OutOfScope;
      decision.detail = "grant scope exceeds its parent grant scope";
      decision.grant = current->id;
      return decision;
    }
    if (!parent->conflict_domains.empty()) {
      if (current->conflict_domains.empty()) {
        decision.outcome = AuthorityOutcome::DomainNotCovered;
        decision.detail = "grant must narrow the parent conflict domain list";
        decision.grant = current->id;
        return decision;
      }
      for (const std::string& domain : current->conflict_domains) {
        if (!parent->covers_domain(domain)) {
          decision.outcome = AuthorityOutcome::DomainNotCovered;
          decision.detail = "grant conflict domain exceeds its parent grant";
          decision.grant = current->id;
          return decision;
        }
      }
    }
    current = parent;
  }
}

AuthorityDecision AuthorityLedger::evaluate(MemberId member, AuthorityAction action,
                                            const RuleScope& scope, std::string_view domain,
                                            Timestamp now,
                                            const MembershipBinding* membership) const {
  AuthorityDecision best;
  best.outcome = AuthorityOutcome::NoGrant;
  best.detail = "member holds no grant for this action";
  bool candidate_seen = false;
  for (const AuthorityGrant& grant : grants_) {
    if (grant.grantee != member || grant.action != action) continue;
    candidate_seen = true;
    AuthorityDecision candidate;
    candidate.grant = grant.id;
    if (!scope_contains_scope(grant.scope, scope, membership)) {
      candidate.outcome = AuthorityOutcome::OutOfScope;
      candidate.detail = "grant scope does not cover the requested scope";
    } else if (!domain.empty() && !grant.covers_domain(domain)) {
      candidate.outcome = AuthorityOutcome::DomainNotCovered;
      candidate.detail = "grant does not cover the conflict domain";
    } else {
      candidate = verify_chain(grant.id, now, membership);
    }
    if (candidate.granted()) return candidate;
    if (!candidate_seen || outcome_priority(candidate.outcome) > outcome_priority(best.outcome)) {
      best = candidate;
    }
  }
  return best;
}

Status AuthorityLedger::restore(std::vector<AuthorityGrant> grants,
                                std::vector<RevocationRecord> revocations, Epoch epoch,
                                Timestamp now) {
  grants_ = std::move(grants);
  revocations_.clear();
  revoked_grants_.clear();
  revoked_bundles_.clear();
  revoked_rules_.clear();
  root_grant_ = GrantId{};
  last_revocation_sequence_ = SequenceNumber{};
  epoch_ = epoch;
  // Persisted revocation order is authoritative: it is validated, never re-sorted. Re-sorting
  // would hide a corrupt or replayed trail behind a plausible-looking sequence.
  for (const AuthorityGrant& grant : grants_) {
    auto status = validate_grant(grant);
    if (!status.ok()) return status;
    if (!grant.digest.is_zero()) {
      auto computed = compute_grant_digest(grant);
      if (!computed) return Status::failure(computed.error);
      if (*computed != grant.digest) {
        return Status::failure(ErrorCode::IntegrityFailure, "restored grant digest does not match",
                               grant.id.to_string());
      }
    }
    if (grant.parent.is_nil()) {
      if (!root_grant_.is_nil()) {
        return Status::failure(ErrorCode::DuplicateIdentity, "persisted state holds two root grants", {});
      }
      root_grant_ = grant.id;
    }
  }
  for (const RevocationRecord& record : revocations) {
    auto status = validate_revocation(record);
    if (!status.ok()) return status;
    if (!record.digest.is_zero()) {
      auto computed = compute_revocation_digest(record);
      if (!computed) return Status::failure(computed.error);
      if (*computed != record.digest) {
        return Status::failure(ErrorCode::IntegrityFailure, "restored revocation digest does not match",
                               record.id.to_string());
      }
    }
    if (!last_revocation_sequence_.is_nil() && record.sequence <= last_revocation_sequence_) {
      return Status::failure(ErrorCode::Reordered, "persisted revocations are not ordered by sequence",
                             record.id.to_string());
    }
    index_revocation(record);
  }
  (void)now;
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------------------

JsonValue grant_to_json(const AuthorityGrant& grant) {
  JsonValue::Array domains;
  for (const std::string& domain : grant.conflict_domains) domains.push_back(JsonValue::text(domain));
  return JsonValue::object({
      {"id", JsonValue::text(grant.id.to_string())},
      {"federation", JsonValue::text(grant.federation.to_string())},
      {"grantor", JsonValue::text(grant.grantor.to_string())},
      {"grantee", JsonValue::text(grant.grantee.to_string())},
      {"parent", JsonValue::text(grant.parent.to_string())},
      {"action", JsonValue::text(authority_action_name(grant.action))},
      {"scope", scope_to_json(grant.scope)},
      {"conflict_domains", JsonValue::array(std::move(domains))},
      {"not_before", JsonValue::integer(grant.not_before.ms)},
      {"not_after", JsonValue::integer(grant.not_after.ms)},
      {"authority_epoch", JsonValue::integer(static_cast<std::int64_t>(grant.authority_epoch.value))},
      {"justification", JsonValue::text(grant.justification)},
      {"digest", JsonValue::text(grant.digest.to_hex())},
  });
}

Result<AuthorityGrant> grant_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<AuthorityGrant>::failure(ErrorCode::MalformedInput, "grant must be a json object", {});
  }
  AuthorityGrant grant;
  auto id = value.require_string("id");
  if (!id) return Result<AuthorityGrant>::failure(id.error);
  auto parsed_id = GrantId::parse(*id);
  if (!parsed_id) return Result<AuthorityGrant>::failure(parsed_id.error);
  grant.id = *parsed_id;
  auto federation = value.require_string("federation");
  if (!federation) return Result<AuthorityGrant>::failure(federation.error);
  auto parsed_federation = FederationId::parse(*federation);
  if (!parsed_federation) return Result<AuthorityGrant>::failure(parsed_federation.error);
  grant.federation = *parsed_federation;
  auto grantor = value.require_string("grantor");
  if (!grantor) return Result<AuthorityGrant>::failure(grantor.error);
  auto parsed_grantor = MemberId::parse(*grantor);
  if (!parsed_grantor) return Result<AuthorityGrant>::failure(parsed_grantor.error);
  grant.grantor = *parsed_grantor;
  auto grantee = value.require_string("grantee");
  if (!grantee) return Result<AuthorityGrant>::failure(grantee.error);
  auto parsed_grantee = MemberId::parse(*grantee);
  if (!parsed_grantee) return Result<AuthorityGrant>::failure(parsed_grantee.error);
  grant.grantee = *parsed_grantee;
  auto parent = value.require_string("parent");
  if (!parent) return Result<AuthorityGrant>::failure(parent.error);
  auto parsed_parent = GrantId::parse(*parent);
  if (!parsed_parent) return Result<AuthorityGrant>::failure(parsed_parent.error);
  grant.parent = *parsed_parent;
  auto action = value.require_string("action");
  if (!action) return Result<AuthorityGrant>::failure(action.error);
  auto parsed_action = authority_action_from_name(*action);
  if (!parsed_action) return Result<AuthorityGrant>::failure(parsed_action.error);
  grant.action = *parsed_action;
  auto scope = value.require_object("scope");
  if (!scope) return Result<AuthorityGrant>::failure(scope.error);
  auto parsed_scope = scope_from_json(**scope);
  if (!parsed_scope) return Result<AuthorityGrant>::failure(parsed_scope.error);
  grant.scope = *parsed_scope;
  if (const JsonValue* domains = value.find("conflict_domains")) {
    if (!domains->is_array()) {
      return Result<AuthorityGrant>::failure(ErrorCode::MalformedInput,
                                             "grant conflict_domains is not an array", {});
    }
    for (const JsonValue& item : domains->array_items()) {
      if (!item.is_string()) {
        return Result<AuthorityGrant>::failure(ErrorCode::MalformedInput,
                                               "grant conflict domain is not a string", {});
      }
      grant.conflict_domains.push_back(item.as_string());
    }
  }
  auto not_before = value.require_int("not_before");
  if (!not_before) return Result<AuthorityGrant>::failure(not_before.error);
  grant.not_before = Timestamp{*not_before};
  auto not_after = value.require_int("not_after");
  if (!not_after) return Result<AuthorityGrant>::failure(not_after.error);
  grant.not_after = Timestamp{*not_after};
  auto epoch = value.require_int_in_range("authority_epoch", 0, INT64_MAX);
  if (!epoch) return Result<AuthorityGrant>::failure(epoch.error);
  grant.authority_epoch = Epoch{static_cast<std::uint64_t>(*epoch)};
  auto justification = value.require_string("justification");
  if (!justification) return Result<AuthorityGrant>::failure(justification.error);
  grant.justification = *justification;
  auto digest = value.require_string("digest");
  if (!digest) return Result<AuthorityGrant>::failure(digest.error);
  auto parsed_digest = Digest::from_hex(*digest);
  if (!parsed_digest) return Result<AuthorityGrant>::failure(parsed_digest.error);
  grant.digest = *parsed_digest;
  auto status = validate_grant(grant);
  if (!status.ok()) return Result<AuthorityGrant>::failure(status.error);
  auto computed = compute_grant_digest(grant);
  if (!computed) return Result<AuthorityGrant>::failure(computed.error);
  if (*computed != grant.digest) {
    return Result<AuthorityGrant>::failure(ErrorCode::IntegrityFailure,
                                           "grant digest does not match content");
  }
  return Result<AuthorityGrant>::success(std::move(grant));
}

JsonValue revocation_to_json(const RevocationRecord& record) {
  std::string target_id;
  switch (record.target) {
    case RevocationTarget::Grant: target_id = record.target_grant().to_string(); break;
    case RevocationTarget::Bundle: target_id = record.target_bundle().to_string(); break;
    case RevocationTarget::Rule: target_id = record.target_rule().to_string(); break;
  }
  return JsonValue::object({
      {"id", JsonValue::text(record.id.to_string())},
      {"federation", JsonValue::text(record.federation.to_string())},
      {"target", JsonValue::text(revocation_target_name(record.target))},
      {"target_id", JsonValue::text(target_id)},
      {"actor_member", JsonValue::text(record.actor_member.to_string())},
      {"actor", JsonValue::text(record.actor)},
      {"authority", JsonValue::text(record.authority.to_string())},
      {"authority_epoch", JsonValue::integer(static_cast<std::int64_t>(record.authority_epoch.value))},
      {"sequence", JsonValue::integer(static_cast<std::int64_t>(record.sequence.value))},
      {"issued_at", JsonValue::integer(record.issued_at.ms)},
      {"effective_at", JsonValue::integer(record.effective_at.ms)},
      {"reason", JsonValue::text(record.reason)},
      {"digest", JsonValue::text(record.digest.to_hex())},
  });
}

Result<RevocationRecord> revocation_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<RevocationRecord>::failure(ErrorCode::MalformedInput,
                                             "revocation must be a json object", {});
  }
  RevocationRecord record;
  auto id = value.require_string("id");
  if (!id) return Result<RevocationRecord>::failure(id.error);
  auto parsed_id = RevocationId::parse(*id);
  if (!parsed_id) return Result<RevocationRecord>::failure(parsed_id.error);
  record.id = *parsed_id;
  auto federation = value.require_string("federation");
  if (!federation) return Result<RevocationRecord>::failure(federation.error);
  auto parsed_federation = FederationId::parse(*federation);
  if (!parsed_federation) return Result<RevocationRecord>::failure(parsed_federation.error);
  record.federation = *parsed_federation;
  auto target = value.require_string("target");
  if (!target) return Result<RevocationRecord>::failure(target.error);
  auto parsed_target = revocation_target_from_name(*target);
  if (!parsed_target) return Result<RevocationRecord>::failure(parsed_target.error);
  record.target = *parsed_target;
  auto target_id = value.require_string("target_id");
  if (!target_id) return Result<RevocationRecord>::failure(target_id.error);
  const char* prefix = record.target == RevocationTarget::Grant ? GrantId::prefix()
                       : record.target == RevocationTarget::Bundle ? PolicyBundleId::prefix()
                                                                   : RuleId::prefix();
  const std::string expected_prefix(prefix);
  if (!has_prefix(*target_id, expected_prefix)) {
    return Result<RevocationRecord>::failure(ErrorCode::MalformedInput,
                                             "revocation target identity has the wrong kind",
                                             escape_preview(*target_id));
  }
  auto parsed_target_id = Id128::from_hex(target_id->substr(expected_prefix.size()));
  if (!parsed_target_id) return Result<RevocationRecord>::failure(parsed_target_id.error);
  record.target_id = *parsed_target_id;
  auto actor_member = value.require_string("actor_member");
  if (!actor_member) return Result<RevocationRecord>::failure(actor_member.error);
  auto parsed_actor = MemberId::parse(*actor_member);
  if (!parsed_actor) return Result<RevocationRecord>::failure(parsed_actor.error);
  record.actor_member = *parsed_actor;
  auto actor = value.require_string("actor");
  if (!actor) return Result<RevocationRecord>::failure(actor.error);
  record.actor = *actor;
  auto authority = value.require_string("authority");
  if (!authority) return Result<RevocationRecord>::failure(authority.error);
  auto parsed_authority = GrantId::parse(*authority);
  if (!parsed_authority) return Result<RevocationRecord>::failure(parsed_authority.error);
  record.authority = *parsed_authority;
  auto epoch = value.require_int_in_range("authority_epoch", 0, INT64_MAX);
  if (!epoch) return Result<RevocationRecord>::failure(epoch.error);
  record.authority_epoch = Epoch{static_cast<std::uint64_t>(*epoch)};
  auto sequence = value.require_int_in_range("sequence", 0, INT64_MAX);
  if (!sequence) return Result<RevocationRecord>::failure(sequence.error);
  record.sequence = SequenceNumber{static_cast<std::uint64_t>(*sequence)};
  auto issued_at = value.require_int("issued_at");
  if (!issued_at) return Result<RevocationRecord>::failure(issued_at.error);
  record.issued_at = Timestamp{*issued_at};
  auto effective_at = value.require_int("effective_at");
  if (!effective_at) return Result<RevocationRecord>::failure(effective_at.error);
  record.effective_at = Timestamp{*effective_at};
  auto reason = value.require_string("reason");
  if (!reason) return Result<RevocationRecord>::failure(reason.error);
  record.reason = *reason;
  auto digest = value.require_string("digest");
  if (!digest) return Result<RevocationRecord>::failure(digest.error);
  auto parsed_digest = Digest::from_hex(*digest);
  if (!parsed_digest) return Result<RevocationRecord>::failure(parsed_digest.error);
  record.digest = *parsed_digest;
  auto status = validate_revocation(record);
  if (!status.ok()) return Result<RevocationRecord>::failure(status.error);
  auto computed = compute_revocation_digest(record);
  if (!computed) return Result<RevocationRecord>::failure(computed.error);
  if (*computed != record.digest) {
    return Result<RevocationRecord>::failure(ErrorCode::IntegrityFailure,
                                             "revocation digest does not match content");
  }
  return Result<RevocationRecord>::success(std::move(record));
}

}  // namespace gpf
