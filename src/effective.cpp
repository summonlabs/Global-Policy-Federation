#include "gpf/effective.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <tuple>

namespace gpf {
namespace {

Status invalid(std::string message, std::string detail = {}) {
  return Status::failure(ErrorCode::InvalidArgument, std::move(message), std::move(detail));
}

void write_value(CanonicalWriter& writer, const SettingValue& value) {
  writer.u8(static_cast<std::uint8_t>(value.type));
  switch (value.type) {
    case SettingValue::Type::Unset:
      break;
    case SettingValue::Type::Boolean:
      writer.boolean(value.boolean);
      break;
    case SettingValue::Type::Integer:
      writer.i64(value.integer);
      break;
    case SettingValue::Type::Text:
      writer.str(value.text);
      break;
  }
}

Id128 id_from_digest(const Digest& digest) {
  Id128 out;
  std::copy(digest.bytes.begin(), digest.bytes.begin() + 16, out.bytes.begin());
  return out;
}

std::string describe_scope(const RuleScope& scope) {
  switch (scope.level) {
    case ScopeLevel::Federation:
      return "federation-wide";
    case ScopeLevel::Member: {
      std::vector<std::string> parts;
      for (MemberId id : scope.members) parts.push_back(id.to_string());
      return "member scope " + join(parts, ",");
    }
    case ScopeLevel::Site: {
      std::vector<std::string> parts;
      for (SiteId id : scope.sites) parts.push_back(id.to_string());
      return "site scope " + join(parts, ",");
    }
  }
  return "unknown scope";
}

}  // namespace

const char* receipt_kind_name(ReceiptKind value) noexcept {
  switch (value) {
    case ReceiptKind::Accepted: return "accepted";
    case ReceiptKind::Applied: return "applied";
    case ReceiptKind::Rejected: return "rejected";
    case ReceiptKind::Overridden: return "overridden";
    case ReceiptKind::Revoked: return "revoked";
    case ReceiptKind::Deferred: return "deferred";
    case ReceiptKind::Superseded: return "superseded";
    case ReceiptKind::ConflictRecorded: return "conflict-recorded";
    case ReceiptKind::Withheld: return "withheld";
  }
  return "unknown";
}

Result<ReceiptKind> receipt_kind_from_name(std::string_view name) {
  if (name == "accepted") return Result<ReceiptKind>::success(ReceiptKind::Accepted);
  if (name == "applied") return Result<ReceiptKind>::success(ReceiptKind::Applied);
  if (name == "rejected") return Result<ReceiptKind>::success(ReceiptKind::Rejected);
  if (name == "overridden") return Result<ReceiptKind>::success(ReceiptKind::Overridden);
  if (name == "revoked") return Result<ReceiptKind>::success(ReceiptKind::Revoked);
  if (name == "deferred") return Result<ReceiptKind>::success(ReceiptKind::Deferred);
  if (name == "superseded") return Result<ReceiptKind>::success(ReceiptKind::Superseded);
  if (name == "conflict-recorded") return Result<ReceiptKind>::success(ReceiptKind::ConflictRecorded);
  if (name == "withheld") return Result<ReceiptKind>::success(ReceiptKind::Withheld);
  return Result<ReceiptKind>::failure(ErrorCode::MalformedInput, "unknown receipt kind",
                                      escape_preview(name));
}

const char* entry_state_name(EntryState value) noexcept {
  switch (value) {
    case EntryState::Absent: return "absent";
    case EntryState::Active: return "active";
    case EntryState::Overridden: return "overridden";
    case EntryState::LastKnownValid: return "last-known-valid";
    case EntryState::Advisory: return "advisory";
    case EntryState::Conflicted: return "conflicted";
    case EntryState::Withheld: return "withheld";
    case EntryState::Revoked: return "revoked";
    case EntryState::Incompatible: return "incompatible";
    case EntryState::Indeterminate: return "indeterminate";
  }
  return "unknown";
}

Result<EntryState> entry_state_from_name(std::string_view name) {
  if (name == "absent") return Result<EntryState>::success(EntryState::Absent);
  if (name == "active") return Result<EntryState>::success(EntryState::Active);
  if (name == "overridden") return Result<EntryState>::success(EntryState::Overridden);
  if (name == "last-known-valid") return Result<EntryState>::success(EntryState::LastKnownValid);
  if (name == "advisory") return Result<EntryState>::success(EntryState::Advisory);
  if (name == "conflicted") return Result<EntryState>::success(EntryState::Conflicted);
  if (name == "withheld") return Result<EntryState>::success(EntryState::Withheld);
  if (name == "revoked") return Result<EntryState>::success(EntryState::Revoked);
  if (name == "incompatible") return Result<EntryState>::success(EntryState::Incompatible);
  if (name == "indeterminate") return Result<EntryState>::success(EntryState::Indeterminate);
  return Result<EntryState>::failure(ErrorCode::MalformedInput, "unknown entry state",
                                     escape_preview(name));
}

bool entry_state_is_binding(EntryState state) noexcept {
  // Only these states may drive an effect. Everything else is explicitly not usable.
  return state == EntryState::Active || state == EntryState::Overridden ||
         state == EntryState::LastKnownValid;
}

// ---------------------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------------------

Status validate_receipt(const Receipt& receipt) {
  if (receipt.federation.is_nil()) return invalid("receipt federation is nil");
  if (receipt.member.is_nil()) return invalid("receipt member is nil");
  if (receipt.site.is_nil()) return invalid("receipt site is nil");
  if (receipt.reason_code.empty() || receipt.reason_code.size() > limits::kMaxIdentifierLength) {
    return invalid("receipt reason code is missing or too long");
  }
  if (!is_valid_utf8(receipt.detail) || receipt.detail.size() > limits::kMaxTextLength) {
    return invalid("receipt detail is invalid or too long");
  }
  return Status::success();
}

ReceiptId derive_receipt_id(const Receipt& receipt) {
  CanonicalWriter writer;
  writer.tag("gpf.receipt.identity.v1");
  writer.id(receipt.federation.value);
  writer.id(receipt.member.value);
  writer.id(receipt.site.value);
  writer.id(receipt.bundle.value);
  writer.u64(receipt.global_generation.value);
  writer.u64(receipt.local_generation.value);
  writer.u8(static_cast<std::uint8_t>(receipt.kind));
  writer.str(receipt.reason_code);
  writer.str(receipt.detail);
  writer.id(receipt.rule.value);
  writer.digest(receipt.rule_digest);
  writer.digest(receipt.bundle_digest);
  writer.id(receipt.override_id.value);
  writer.i64(receipt.at.ms);
  ReceiptId out;
  out.value = id_from_digest(writer.digest());
  return out;
}

Result<Digest> compute_receipt_digest(const Receipt& receipt) {
  CanonicalWriter writer;
  writer.tag("gpf.receipt.v1");
  writer.id(receipt.id.value);
  writer.id(receipt.federation.value);
  writer.id(receipt.member.value);
  writer.id(receipt.site.value);
  writer.id(receipt.bundle.value);
  writer.u64(receipt.global_generation.value);
  writer.u64(receipt.local_generation.value);
  writer.u8(static_cast<std::uint8_t>(receipt.kind));
  writer.str(receipt.reason_code);
  writer.str(receipt.detail);
  writer.id(receipt.rule.value);
  writer.digest(receipt.rule_digest);
  writer.digest(receipt.bundle_digest);
  writer.id(receipt.override_id.value);
  writer.i64(receipt.at.ms);
  writer.u64(receipt.sequence.value);
  return Result<Digest>::success(writer.digest());
}

Status seal_receipt(Receipt& receipt) {
  if (receipt.id.is_nil()) receipt.id = derive_receipt_id(receipt);
  auto digest = compute_receipt_digest(receipt);
  if (!digest) return Status::failure(digest.error);
  receipt.digest = *digest;
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Conflicts
// ---------------------------------------------------------------------------------------

Status validate_conflict(const ConflictRecord& record) {
  if (!is_valid_identifier(record.domain)) return invalid("conflict domain is not a valid identifier");
  if (!is_valid_identifier(record.subject)) return invalid("conflict subject is not a valid identifier");
  if (record.participants.size() < 2) return invalid("a conflict needs at least two participants");
  if (record.reason_code.empty()) return invalid("conflict carries no reason code");
  if (!is_valid_utf8(record.detail)) return invalid("conflict detail is not valid UTF-8");
  return Status::success();
}

ConflictId derive_conflict_id(const ConflictRecord& record) {
  CanonicalWriter writer;
  writer.tag("gpf.conflict.identity.v1");
  writer.str(record.domain);
  writer.str(record.subject);
  writer.u8(static_cast<std::uint8_t>(record.rule_class));
  writer.str(record.reason_code);
  std::vector<RuleId> participants = record.participants;
  std::sort(participants.begin(), participants.end());
  writer.u64(static_cast<std::uint64_t>(participants.size()));
  for (RuleId id : participants) writer.id(id.value);
  ConflictId out;
  out.value = id_from_digest(writer.digest());
  return out;
}

Result<Digest> compute_conflict_digest(const ConflictRecord& record) {
  CanonicalWriter writer;
  writer.tag("gpf.conflict.v1");
  writer.id(record.id.value);
  writer.str(record.domain);
  writer.str(record.subject);
  writer.u8(static_cast<std::uint8_t>(record.rule_class));
  std::vector<RuleId> participants = record.participants;
  std::sort(participants.begin(), participants.end());
  writer.u64(static_cast<std::uint64_t>(participants.size()));
  for (RuleId id : participants) writer.id(id.value);
  std::vector<PolicyBundleId> bundles = record.bundles;
  std::sort(bundles.begin(), bundles.end());
  writer.u64(static_cast<std::uint64_t>(bundles.size()));
  for (PolicyBundleId id : bundles) writer.id(id.value);
  writer.str(record.reason_code);
  writer.str(record.detail);
  writer.i64(record.detected_at.ms);
  writer.boolean(record.contained);
  return Result<Digest>::success(writer.digest());
}

Status seal_conflict(ConflictRecord& record) {
  if (record.id.is_nil()) record.id = derive_conflict_id(record);
  auto digest = compute_conflict_digest(record);
  if (!digest) return Status::failure(digest.error);
  record.digest = *digest;
  return Status::success();
}

const EffectiveEntry* EffectivePolicy::find(std::string_view domain, std::string_view subject) const noexcept {
  for (const EffectiveEntry& entry : entries) {
    if (entry.domain == domain && entry.subject == subject) return &entry;
  }
  return nullptr;
}

EffectiveEntry explain_subject(const EffectivePolicy& policy, std::string_view domain,
                               std::string_view subject) {
  const EffectiveEntry* found = policy.find(domain, subject);
  if (found != nullptr) return *found;
  EffectiveEntry entry;
  entry.domain = std::string(domain);
  entry.subject = std::string(subject);
  entry.state = EntryState::Absent;
  entry.reason_code = "no-policy-addresses-subject";
  entry.detail = "no accepted, local or overridden policy addresses this subject at this site";
  entry.explanation.push_back("absent: no policy addresses " + entry.domain + "/" + entry.subject +
                              " for this site");
  return entry;
}

}  // namespace gpf
namespace gpf {
namespace {

struct BundleRef {
  const PolicyBundle* bundle{nullptr};
  bool local{false};
};

struct RuleView {
  const Rule* rule{nullptr};
  const PolicyBundle* bundle{nullptr};
  bool local{false};
  Digest rule_digest{};
  Digest bundle_digest{};
  bool usable{false};
  bool last_known_valid{false};
  EntryState blocked_state{EntryState::Withheld};
  std::string reason_code;
  std::string detail;
  NegotiationOutcome capability_outcome{NegotiationOutcome::Satisfied};
  std::string capability_detail;
};

struct Resolution {
  EntryState state{EntryState::Absent};
  const RuleView* winner{nullptr};
  std::vector<const RuleView*> participants;
  RuleClass rule_class{RuleClass::Default};
  std::string reason_code;
  std::string detail;
  // Override permission of the governing policy. Where several mandatory rules agree on a value
  // but disagree about override rights, the most restrictive permission governs: a prohibition is
  // never erased by agreeing with a permissive twin.
  OverridePermission permission{OverridePermission::Allowed};
};

OverridePermission most_restrictive_permission(const std::vector<const RuleView*>& views) {
  OverridePermission result = OverridePermission::Allowed;
  for (const RuleView* view : views) {
    if (static_cast<std::uint8_t>(view->rule->override_permission) <
        static_cast<std::uint8_t>(result)) {
      result = view->rule->override_permission;
    }
  }
  return result;
}

bool same_value_for_all(const std::vector<const RuleView*>& views) {
  if (views.empty()) return true;
  for (const RuleView* view : views) {
    if (!(view->rule->value == views.front()->rule->value)) return false;
  }
  return true;
}

RuleClass max_rule_class(RuleClass a, RuleClass b) noexcept {
  return static_cast<std::uint8_t>(a) >= static_cast<std::uint8_t>(b) ? a : b;
}

// Deterministic tie-break between rules of equal standing. Never arrival order, never identity
// of the connection, never wall-clock: declared version first, then the newer policy generation,
// then stable identity. Fresh policy is preferred to policy that is only last-known-valid.
const RuleView* select_winner(const std::vector<const RuleView*>& candidates) {
  const RuleView* best = nullptr;
  for (const RuleView* candidate : candidates) {
    if (best == nullptr) {
      best = candidate;
      continue;
    }
    if (best->last_known_valid != candidate->last_known_valid) {
      best = best->last_known_valid ? candidate : best;
      continue;
    }
    if (best->rule->version != candidate->rule->version) {
      best = (best->rule->version < candidate->rule->version) ? candidate : best;
      continue;
    }
    if (best->bundle->global_generation != candidate->bundle->global_generation) {
      best = (best->bundle->global_generation < candidate->bundle->global_generation) ? candidate : best;
      continue;
    }
    if (candidate->rule->id < best->rule->id) best = candidate;
  }
  return best;
}

std::vector<const RuleView*> with_max_precedence(const std::vector<const RuleView*>& candidates) {
  std::uint32_t maximum = 0;
  for (const RuleView* candidate : candidates) {
    if (candidate->rule->precedence > maximum) maximum = candidate->rule->precedence;
  }
  std::vector<const RuleView*> out;
  for (const RuleView* candidate : candidates) {
    if (candidate->rule->precedence == maximum) out.push_back(candidate);
  }
  return out;
}

const char* blocking_reason_for(EntryState state) {
  switch (state) {
    case EntryState::Revoked: return reasons::kPolicyRevoked;
    case EntryState::Incompatible: return reasons::kCapabilityUnsatisfied;
    case EntryState::Indeterminate: return reasons::kCapabilityUnknown;
    case EntryState::Withheld: return reasons::kPolicyWithheldStale;
    default: return reasons::kAuthorityDenied;
  }
}

void sort_views(std::vector<const RuleView*>& views) {
  std::sort(views.begin(), views.end(), [](const RuleView* a, const RuleView* b) {
    return a->rule->id < b->rule->id;
  });
}

int blocked_severity(EntryState state) {
  switch (state) {
    case EntryState::Revoked: return 4;
    case EntryState::Incompatible: return 3;
    case EntryState::Indeterminate: return 2;
    case EntryState::Withheld: return 1;
    default: return 0;
  }
}

// Precedence contract, applied in this exact order:
//   1. class: mandatory binds over default, default over advisory;
//   2. for mandatory rules, the explicitly declared precedence value;
//   3. for default and advisory rules, local policy authored by the site itself over
//      federated policy (local sovereignty for non-binding policy).
// Everything else is a conflict and is contained to the affected subject.
Resolution resolve_subject(const std::vector<RuleView>& views) {
  Resolution resolution;
  std::vector<const RuleView*> usable;
  std::vector<const RuleView*> blocked;
  for (const RuleView& view : views) {
    if (view.usable) {
      usable.push_back(&view);
    } else {
      blocked.push_back(&view);
    }
  }
  if (usable.empty()) {
    sort_views(blocked);
    std::vector<const RuleView*> most_severe;
    int severity = -1;
    for (const RuleView* view : blocked) {
      const int candidate = blocked_severity(view->blocked_state);
      if (candidate > severity) {
        severity = candidate;
        most_severe.clear();
      }
      if (candidate == severity) most_severe.push_back(view);
    }
    if (!most_severe.empty()) {
      resolution.state = most_severe.front()->blocked_state;
      resolution.reason_code = most_severe.front()->reason_code.empty()
                                   ? blocking_reason_for(resolution.state)
                                   : most_severe.front()->reason_code;
      resolution.detail = most_severe.front()->detail;
      for (const RuleView* view : most_severe) resolution.participants.push_back(view);
    }
    return resolution;
  }

  RuleClass highest = RuleClass::Advisory;
  for (const RuleView* view : usable) highest = max_rule_class(highest, view->rule->rule_class);
  std::vector<const RuleView*> candidates;
  for (const RuleView* view : usable) {
    if (view->rule->rule_class == highest) candidates.push_back(view);
  }
  resolution.rule_class = highest;

  if (highest == RuleClass::Mandatory) {
    std::vector<const RuleView*> top = with_max_precedence(candidates);
    resolution.permission = most_restrictive_permission(top);
    // The tier is recorded even when the rules agree: an override is bound to the rule its author
    // saw, and that rule is still authoritative while it belongs to the agreeing tier.
    resolution.participants = top;
    if (same_value_for_all(top)) {
      resolution.winner = select_winner(top);
      resolution.state = resolution.winner->last_known_valid ? EntryState::LastKnownValid : EntryState::Active;
      resolution.reason_code = resolution.winner->last_known_valid ? reasons::kPolicyLastKnownValid
                                                                  : "mandatory-policy-applied";
      resolution.detail = "mandatory policy from a single declared precedence tier agrees";
      return resolution;
    }
    resolution.state = EntryState::Conflicted;
    resolution.reason_code = reasons::kContradictoryMandatory;
    resolution.detail = "mandatory rules in the same precedence tier disagree on the value";
    return resolution;
  }

  if (highest == RuleClass::Default) {
    std::vector<const RuleView*> locals;
    for (const RuleView* view : candidates) {
      if (view->local) locals.push_back(view);
    }
    const std::vector<const RuleView*>& tier = locals.empty() ? candidates : locals;
    if (same_value_for_all(tier)) {
      resolution.winner = select_winner(tier);
      resolution.state = resolution.winner->last_known_valid ? EntryState::LastKnownValid : EntryState::Active;
      resolution.reason_code = resolution.winner->last_known_valid ? reasons::kPolicyLastKnownValid
                                                                  : "default-policy-applied";
      resolution.detail = locals.empty() ? "federated default policy applies"
                                         : "local default policy supersedes federated defaults";
      return resolution;
    }
    resolution.state = EntryState::Conflicted;
    resolution.reason_code = reasons::kContradictoryDefault;
    resolution.detail = "default rules of the same standing disagree on the value";
    resolution.participants = tier;
    return resolution;
  }

  // Advisory policy never binds. A disagreement among advisory rules is recorded, and the
  // resulting entry stays advisory rather than becoming an authoritative conflict.
  resolution.state = EntryState::Advisory;
  resolution.winner = select_winner(candidates);
  if (same_value_for_all(candidates)) {
    resolution.reason_code = reasons::kAdvisoryOnly;
    resolution.detail = "advisory policy: informational only";
  } else {
    resolution.reason_code = reasons::kContradictoryAdvisory;
    resolution.detail = "advisory rules disagree; advisory policy never binds";
    resolution.participants = candidates;
  }
  return resolution;
}

}  // namespace

Result<EffectivePolicy> compile_effective_policy(const EffectivePolicyInput& input) {
  EffectivePolicy policy;
  policy.federation = input.federation;
  policy.member = input.member;
  policy.site = input.site;
  policy.compiled_at = input.now;
  policy.runtime_version = input.runtime_version;
  policy.partitioned = input.partitioned;

  // ---- 1. Applicable policy -------------------------------------------------------------
  std::vector<BundleRef> applicable;
  const auto admit = [&](const PolicyBundle& bundle, bool local,
                         std::vector<BundleRef>& target) -> Status {
    const Status status = input.verify_bundle_integrity ? verify_bundle(bundle) : validate_bundle(bundle);
    if (!status.ok()) return status;
    if (!bundle_applies_to_site(bundle, input.member, input.site)) return Status::success();
    target.push_back(BundleRef{&bundle, local});
    return Status::success();
  };
  for (const PolicyBundle& bundle : input.accepted_bundles) {
    const Status status = admit(bundle, false, applicable);
    if (!status.ok()) return Result<EffectivePolicy>::failure(status.error);
  }
  for (const PolicyBundle& bundle : input.local_bundles) {
    const Status status = admit(bundle, true, applicable);
    if (!status.ok()) return Result<EffectivePolicy>::failure(status.error);
  }
  std::sort(applicable.begin(), applicable.end(), [](const BundleRef& a, const BundleRef& b) {
    return a.bundle->id < b.bundle->id;
  });

  // A newer generation from the same publisher for the same scope replaces the older one. This
  // is declared revision order from a single authority, not arrival order and not a vote between
  // independent publishers; different publishers still have to agree or be reported as conflicted.
  std::map<std::string, Generation> newest_by_publisher;
  for (const BundleRef& ref : applicable) {
    const std::string publisher =
        (ref.local ? "local|" : "federated|") + ref.bundle->issuer_member.to_string() + "|" +
        describe_scope(ref.bundle->scope);
    auto found = newest_by_publisher.find(publisher);
    if (found == newest_by_publisher.end() || found->second < ref.bundle->global_generation) {
      newest_by_publisher[publisher] = ref.bundle->global_generation;
    }
  }

  // Generations are read, never fabricated: while partitioned the newest global generation stays
  // whatever the accepted policy already carries.
  for (const BundleRef& ref : applicable) {
    if (ref.local) {
      if (ref.bundle->global_generation > policy.local_generation) {
        policy.local_generation = ref.bundle->global_generation;
      }
    } else if (ref.bundle->global_generation > policy.global_generation) {
      policy.global_generation = ref.bundle->global_generation;
    }
  }

  // ---- 2. Per-rule usability ------------------------------------------------------------
  std::vector<RuleView> views;
  std::vector<Receipt> superseded_receipts;
  std::map<std::string, std::vector<std::size_t>> by_key;
  std::size_t considered = 0;
  for (const BundleRef& ref : applicable) {
    const PolicyBundle& bundle = *ref.bundle;
    const bool runtime_ok = bundle.required_runtime.backward_compatible_with(input.runtime_version);
    const bool catalog_ok = bundle.capability_catalog_generation <= input.capability_catalog.generation;
    const bool bundle_revoked =
        input.authority != nullptr && input.authority->is_bundle_revoked(bundle.id, input.now);
    const bool bundle_expired = bundle_is_expired_at(bundle, input.now);
    const bool bundle_not_yet =
        bundle.effective_from.ms != 0 && input.now.ms < bundle.effective_from.ms;
    const std::string publisher =
        (ref.local ? "local|" : "federated|") + bundle.issuer_member.to_string() + "|" +
        describe_scope(bundle.scope);
    const Generation newest = newest_by_publisher[publisher];
    const bool superseded = bundle.global_generation < newest;

    for (const Rule& rule : bundle.rules) {
      if (!rule.applies_to(input.member, input.site)) continue;
      if (++considered > input.max_rules) {
        return Result<EffectivePolicy>::failure(
            ErrorCode::TooLarge, "compilation exceeds the configured rule budget",
            std::to_string(considered));
      }
      policy.rules_considered = considered;
      RuleView view;
      view.rule = &rule;
      view.bundle = &bundle;
      view.local = ref.local;
      auto rule_digest = compute_rule_digest(rule);
      if (!rule_digest) return Result<EffectivePolicy>::failure(rule_digest.error);
      view.rule_digest = *rule_digest;
      view.bundle_digest = bundle.integrity_digest;

      const bool rule_revoked =
          input.authority != nullptr && input.authority->is_rule_revoked(rule.id, input.now);

      if (superseded) {
        // A newer generation from the same publisher replaced this rule. The rule is not applied
        // and the fact that it was replaced is recorded rather than silently dropped.
        view.usable = false;
        view.blocked_state = EntryState::Absent;  // excluded from resolution; receipt carries the fact
        view.reason_code = reasons::kGenerationSuperseded;
        view.detail = "replaced by generation " + std::to_string(newest.value) +
                      " from the same publisher and scope";
        ++policy.rules_superseded;
        Receipt receipt;
        receipt.federation = input.federation;
        receipt.member = input.member;
        receipt.site = input.site;
        receipt.bundle = bundle.id;
        receipt.global_generation = ref.local ? Generation{} : bundle.global_generation;
        receipt.local_generation = ref.local ? bundle.global_generation : Generation{};
        receipt.kind = ReceiptKind::Superseded;
        receipt.reason_code = reasons::kGenerationSuperseded;
        receipt.detail = view.detail;
        receipt.rule = rule.id;
        receipt.rule_digest = view.rule_digest;
        receipt.bundle_digest = view.bundle_digest;
        receipt.at = input.now;
        superseded_receipts.push_back(std::move(receipt));
        continue;
      }

      if (bundle_revoked || rule_revoked) {
        view.blocked_state = EntryState::Revoked;
        view.reason_code = bundle_revoked ? reasons::kPolicyRevoked : reasons::kRuleRevoked;
        view.detail = bundle_revoked ? "publishing bundle was revoked" : "rule was revoked";
      } else if (bundle_expired || rule.is_expired_at(input.now)) {
        view.blocked_state = EntryState::Withheld;
        view.reason_code = reasons::kPolicyExpired;
        view.detail = "policy has expired and may not be used";
      } else if (bundle_not_yet || (rule.effective_from.ms != 0 && input.now.ms < rule.effective_from.ms)) {
        view.blocked_state = EntryState::Withheld;
        view.reason_code = reasons::kPolicyNotYetEffective;
        view.detail = "policy is not yet effective";
      } else if (!runtime_ok) {
        view.blocked_state = EntryState::Incompatible;
        view.reason_code = reasons::kRuntimeIncompatible;
        view.detail = "bundle requires runtime " + bundle.required_runtime.to_string() +
                      " but this site runs " + input.runtime_version.to_string();
      } else if (!catalog_ok) {
        view.blocked_state = EntryState::Indeterminate;
        view.reason_code = reasons::kCatalogStale;
        view.detail = "bundle was authored against capability catalog generation " +
                      std::to_string(bundle.capability_catalog_generation.value) +
                      " which this site has not been told about";
      } else {
        bool incompatible = false;
        bool deferred = false;
        for (const CapabilityRequirement& requirement : rule.capability_requirements) {
          const NegotiationOutcome outcome =
              negotiate_capability(requirement, input.capabilities, input.capability_catalog);
          if (outcome == NegotiationOutcome::Satisfied) {
            view.capability_outcome = NegotiationOutcome::Satisfied;
            continue;
          }
          if (view.capability_outcome == NegotiationOutcome::Satisfied) view.capability_outcome = outcome;
          const std::string description =
              std::string(requirement.capability) + " >= " + requirement.min_version.to_string() +
              " (" + negotiation_outcome_name(outcome) + ")";
          view.capability_detail =
              view.capability_detail.empty() ? description : view.capability_detail + "; " + description;
          if (requirement.optional) continue;  // recorded, but not blocking
          if (outcome == NegotiationOutcome::UnsupportedCapability ||
              outcome == NegotiationOutcome::VersionMismatch) {
            incompatible = true;
          } else {
            deferred = true;
          }
        }
        if (incompatible) {
          view.blocked_state = EntryState::Incompatible;
          view.reason_code = reasons::kCapabilityUnsatisfied;
          view.detail = "capability prerequisites are not satisfied: " + view.capability_detail;
        } else if (deferred) {
          view.blocked_state = EntryState::Indeterminate;
          view.reason_code = view.capability_outcome == NegotiationOutcome::CatalogStale
                                 ? reasons::kCatalogStale
                                 : reasons::kCapabilityUnknown;
          view.detail = "capability prerequisites cannot be decided yet: " + view.capability_detail;
        } else if (!ref.local && input.partitioned) {
          // Partition behavior: federated policy stays effective only where the declared
          // staleness policy permits it. Local policy is never stale.
          const StalenessPolicy effective =
              rule.staleness.mode == StalenessPolicy::Mode::AllowLastKnownValid ? rule.staleness
                                                                                : bundle.staleness;
          Millis age = input.now.ms - input.last_contact_at.ms;
          if (age < 0) age = 0;
          if (effective.mode == StalenessPolicy::Mode::AllowLastKnownValid &&
              age <= effective.max_staleness_ms) {
            view.usable = true;
            view.last_known_valid = true;
            view.reason_code = reasons::kPolicyLastKnownValid;
            view.detail = "federation contact is not current; policy is last-known-valid within the "
                          "declared window of " + std::to_string(effective.max_staleness_ms) + " ms";
          } else {
            view.blocked_state = EntryState::Withheld;
            view.reason_code = reasons::kPolicyWithheldStale;
            view.detail = "federation contact is not current and this policy does not permit "
                          "last-known-valid use";
          }
        } else {
          view.usable = true;
          view.reason_code = "policy-current";
          view.detail = "policy is current";
        }
      }

      const std::size_t index = views.size();
      views.push_back(std::move(view));
      by_key[views[index].rule->key()].push_back(index);
    }
  }

  // ---- 3. Resolve each subject ----------------------------------------------------------
  std::map<std::string, std::size_t> entry_index;
  std::map<std::string, const Rule*> governing_rule;
  std::map<std::string, OverridePermission> governing_permission;
  // Value-typed binding records: the agreeing tier is read after the per-subject views are gone,
  // so it must not hold pointers into them.
  struct TierBinding {
    RuleId rule;
    Digest rule_digest;
    Generation generation;
    Digest bundle_digest;
  };
  std::map<std::string, std::vector<TierBinding>> governing_tier;
  std::vector<Receipt> receipts = std::move(superseded_receipts);
  const auto make_receipt = [&](const RuleView* view, ReceiptKind kind, const std::string& reason_code,
                                const std::string& detail) {
    Receipt receipt;
    receipt.federation = input.federation;
    receipt.member = input.member;
    receipt.site = input.site;
    receipt.bundle = view->bundle->id;
    receipt.global_generation = view->local ? Generation{} : view->bundle->global_generation;
    receipt.local_generation = view->local ? view->bundle->global_generation : Generation{};
    receipt.kind = kind;
    receipt.reason_code = reason_code;
    receipt.detail = detail;
    receipt.rule = view->rule->id;
    receipt.rule_digest = view->rule_digest;
    receipt.bundle_digest = view->bundle_digest;
    receipt.at = input.now;
    receipts.push_back(std::move(receipt));
  };

  for (const auto& group : by_key) {
    std::vector<RuleView> group_views;
    for (std::size_t index : group.second) group_views.push_back(views[index]);
    const Resolution resolution = resolve_subject(group_views);
    EffectiveEntry entry;
    entry.domain = group_views.front().rule->domain;
    entry.subject = group_views.front().rule->subject;
    entry.state = resolution.state;
    entry.effective_class = resolution.rule_class;
    entry.reason_code = resolution.reason_code;
    entry.detail = resolution.detail;
    entry.capability_outcome = resolution.winner != nullptr ? resolution.winner->capability_outcome
                                                            : group_views.front().capability_outcome;
    entry.capability_detail = resolution.winner != nullptr ? resolution.winner->capability_detail
                                                           : group_views.front().capability_detail;

    if (resolution.winner != nullptr) {
      const RuleView& winner = *resolution.winner;
      entry.value = winner.rule->value;
      entry.source_rule = winner.rule->id;
      entry.source_bundle = winner.bundle->id;
      entry.source_generation = winner.bundle->global_generation;
      entry.source_rule_digest = winner.rule_digest;
      entry.source_bundle_digest = winner.bundle_digest;
      governing_rule[group.first] = winner.rule;
      governing_permission[group.first] = resolution.permission;
      std::vector<TierBinding> tier;
      tier.reserve(resolution.participants.size());
      for (const RuleView* participant : resolution.participants) {
        tier.push_back(TierBinding{participant->rule->id, participant->rule_digest,
                                   participant->bundle->global_generation,
                                   participant->bundle->integrity_digest});
      }
      governing_tier[group.first] = std::move(tier);
      entry.explanation.push_back("value " + winner.rule->value.to_display_string() + " from rule " +
                                  winner.rule->id.to_string() + " (" +
                                  rule_class_name(winner.rule->rule_class) + ", version " +
                                  winner.rule->version.to_string() + ")");
      entry.explanation.push_back("source bundle " + winner.bundle->id.to_string() +
                                  (winner.local ? " (site-local)" : " (federated)") +
                                  " generation " + std::to_string(winner.bundle->global_generation.value));
      entry.explanation.push_back("applicability: " + describe_scope(winner.rule->scope));
      if (!winner.capability_detail.empty()) {
        entry.explanation.push_back("capability prerequisites: " + winner.capability_detail);
      }
      if (winner.last_known_valid) {
        entry.explanation.push_back(
            "last-known-valid: " + winner.detail + "; last verified contact " +
            input.last_contact_at.to_iso8601());
      }
      if (entry.state == EntryState::Advisory) {
        entry.explanation.push_back("advisory policy is informational and does not bind");
      }
      if (entry.state == EntryState::LastKnownValid || entry.state == EntryState::Active) {
        make_receipt(&winner, ReceiptKind::Applied, resolution.reason_code, winner.detail);
      }
    }

    if (entry.explanation.empty()) {
      // A subject whose policy cannot be used still explains itself: the state and the reason are
      // part of the answer, and so are the rules that were considered.
      entry.explanation.push_back(std::string("state ") + entry_state_name(entry.state) + ": " +
                                  (entry.detail.empty() ? entry.reason_code : entry.detail));
      if (!resolution.participants.empty()) {
        std::vector<const RuleView*> ordered = resolution.participants;
        sort_views(ordered);
        for (const RuleView* participant : ordered) {
          entry.explanation.push_back(
              "considered rule " + participant->rule->id.to_string() + " (" +
              rule_class_name(participant->rule->rule_class) + ") from bundle " +
              participant->bundle->id.to_string() + ": " + participant->reason_code + " - " +
              participant->detail);
        }
      }
    }

    if (resolution.state == EntryState::Conflicted) {
      ConflictRecord conflict;
      conflict.domain = entry.domain;
      conflict.subject = entry.subject;
      conflict.rule_class = resolution.rule_class;
      conflict.reason_code = resolution.reason_code;
      conflict.detail = resolution.detail;
      conflict.detected_at = input.now;
      conflict.contained = true;
      for (const RuleView* participant : resolution.participants) {
        conflict.participants.push_back(participant->rule->id);
        conflict.bundles.push_back(participant->bundle->id);
      }
      std::sort(conflict.participants.begin(), conflict.participants.end());
      conflict.participants.erase(std::unique(conflict.participants.begin(), conflict.participants.end()),
                                  conflict.participants.end());
      std::sort(conflict.bundles.begin(), conflict.bundles.end());
      conflict.bundles.erase(std::unique(conflict.bundles.begin(), conflict.bundles.end()),
                             conflict.bundles.end());
      if (policy.conflicts.size() >= input.max_conflicts) {
        return Result<EffectivePolicy>::failure(
            ErrorCode::TooLarge, "compilation produced more conflicts than the configured budget",
            std::to_string(policy.conflicts.size()));
      }
      auto sealed = seal_conflict(conflict);
      if (!sealed.ok()) return Result<EffectivePolicy>::failure(sealed.error);
      entry.conflict = conflict.id;
      entry.explanation.push_back("conflict " + conflict.id.to_string() + ": " + conflict.detail +
                                  " (contained to " + conflict.domain + "/" + conflict.subject + ")");
      policy.conflicts.push_back(std::move(conflict));

      Receipt receipt;
      receipt.federation = input.federation;
      receipt.member = input.member;
      receipt.site = input.site;
      receipt.bundle = policy.conflicts.back().bundles.empty() ? PolicyBundleId{} : policy.conflicts.back().bundles.front();
      receipt.kind = ReceiptKind::ConflictRecorded;
      receipt.reason_code = policy.conflicts.back().reason_code;
      receipt.detail = policy.conflicts.back().detail;
      receipt.at = input.now;
      receipts.push_back(std::move(receipt));
    }

    if (resolution.state == EntryState::Advisory && resolution.winner != nullptr &&
        resolution.participants.size() > 1) {
      ConflictRecord conflict;
      conflict.domain = entry.domain;
      conflict.subject = entry.subject;
      conflict.rule_class = RuleClass::Advisory;
      conflict.reason_code = resolution.reason_code;
      conflict.detail = resolution.detail;
      conflict.detected_at = input.now;
      conflict.contained = true;
      for (const RuleView* participant : resolution.participants) {
        conflict.participants.push_back(participant->rule->id);
        conflict.bundles.push_back(participant->bundle->id);
      }
      std::sort(conflict.participants.begin(), conflict.participants.end());
      conflict.participants.erase(std::unique(conflict.participants.begin(), conflict.participants.end()),
                                  conflict.participants.end());
      std::sort(conflict.bundles.begin(), conflict.bundles.end());
      conflict.bundles.erase(std::unique(conflict.bundles.begin(), conflict.bundles.end()),
                             conflict.bundles.end());
      auto sealed = seal_conflict(conflict);
      if (!sealed.ok()) return Result<EffectivePolicy>::failure(sealed.error);
      entry.conflict = conflict.id;
      policy.conflicts.push_back(std::move(conflict));
    }

    const std::size_t index = policy.entries.size();
    entry_index[group.first] = index;
    policy.entries.push_back(std::move(entry));
  }

  // Blocked rules always leave evidence, whether or not their subject has a usable rule.
  for (const RuleView& view : views) {
    if (view.usable) continue;
    switch (view.blocked_state) {
      case EntryState::Withheld:
        ++policy.rules_withheld;
        make_receipt(&view, ReceiptKind::Withheld, view.reason_code, view.detail);
        break;
      case EntryState::Revoked:
        ++policy.rules_revoked;
        make_receipt(&view, ReceiptKind::Revoked, view.reason_code, view.detail);
        break;
      case EntryState::Incompatible:
        ++policy.rules_rejected;
        make_receipt(&view, ReceiptKind::Rejected, view.reason_code, view.detail);
        break;
      case EntryState::Indeterminate:
        ++policy.rules_deferred;
        make_receipt(&view, ReceiptKind::Deferred, view.reason_code, view.detail);
        break;
      default:
        break;
    }
  }
  for (const EffectiveEntry& entry : policy.entries) {
    if (entry_state_is_binding(entry.state)) ++policy.rules_applied;
  }

  // ---- 4. Local overrides ---------------------------------------------------------------
  std::vector<const LocalOverride*> overrides;
  for (const LocalOverride& record : input.overrides) {
    auto status = validate_override(record);
    if (!status.ok()) return Result<EffectivePolicy>::failure(status.error);
    if (record.federation != input.federation) continue;
    if (record.site != input.site || record.member != input.member) continue;
    auto computed = compute_override_digest(record);
    if (!computed) return Result<EffectivePolicy>::failure(computed.error);
    if (*computed != record.digest) {
      return Result<EffectivePolicy>::failure(ErrorCode::IntegrityFailure,
                                              "override digest does not match content",
                                              record.id.to_string());
    }
    if (record.local_generation > policy.local_generation) policy.local_generation = record.local_generation;
    overrides.push_back(&record);
  }
  std::sort(overrides.begin(), overrides.end(),
            [](const LocalOverride* a, const LocalOverride* b) { return a->id < b->id; });

  for (const LocalOverride* record : overrides) {
    const std::string key = record->key();
    Receipt receipt;
    receipt.federation = input.federation;
    receipt.member = input.member;
    receipt.site = input.site;
    receipt.override_id = record->id;
    receipt.local_generation = record->local_generation;
    receipt.at = input.now;
    auto refuse = [&](const char* code, const std::string& detail) {
      ++policy.overrides_refused;
      receipt.kind = ReceiptKind::Rejected;
      receipt.reason_code = code;
      receipt.detail = detail;
      receipts.push_back(receipt);
      const auto found = entry_index.find(key);
      if (found != entry_index.end()) {
        EffectiveEntry& entry = policy.entries[found->second];
        entry.explanation.push_back("override " + record->id.to_string() + " refused: " + detail);
      }
    };

    const auto found = entry_index.find(key);
    if (found == entry_index.end()) {
      refuse(reasons::kOverrideWithoutBase,
             "no accepted policy establishes a base for this override at this site");
      continue;
    }
    EffectiveEntry& entry = policy.entries[found->second];
    const auto governing = governing_rule.find(key);
    if (governing == governing_rule.end() || entry.state != EntryState::Active ||
        entry.effective_class != RuleClass::Mandatory) {
      refuse(reasons::kOverrideNotApplicable,
             entry.state == EntryState::Active
                 ? "only mandatory policy can be overridden, and the governing policy is " +
                       std::string(rule_class_name(entry.effective_class))
                 : "governing policy is not active, so no override base exists: " +
                       std::string(entry_state_name(entry.state)));
      continue;
    }
    const Rule& base = *governing->second;
    // Generation-bound to the exact rule and generation the author overrode. While that rule is
    // still part of the agreeing authoritative tier the override stands, even if a tie-break chose
    // a twin to report as the source; once the rule is replaced, the override is superseded.
    bool bound_to_authoritative_rule = false;
    const auto tier = governing_tier.find(key);
    if (tier != governing_tier.end()) {
      for (const TierBinding& candidate : tier->second) {
        if (record->target_rule == candidate.rule &&
            record->target_rule_digest == candidate.rule_digest &&
            record->target_bundle_generation == candidate.generation &&
            record->target_bundle_digest == candidate.bundle_digest) {
          bound_to_authoritative_rule = true;
          break;
        }
      }
    }
    if (!bound_to_authoritative_rule) {
      receipt.kind = ReceiptKind::Superseded;
      receipt.reason_code = reasons::kOverrideSuperseded;
      receipt.detail = "override was bound to a different rule or generation than the governing policy";
      receipt.bundle = entry.source_bundle;
      receipt.global_generation = entry.source_generation;
      receipt.rule = entry.source_rule;
      receipt.rule_digest = entry.source_rule_digest;
      receipt.bundle_digest = entry.source_bundle_digest;
      receipts.push_back(receipt);
      entry.explanation.push_back("override " + record->id.to_string() +
                                  " superseded: bound to an older rule or generation");
      continue;
    }
    if (record->is_expired_at(input.now)) {
      refuse(reasons::kPolicyExpired, "override has expired");
      continue;
    }
    const auto permission_entry = governing_permission.find(key);
    const OverridePermission effective_permission = permission_entry != governing_permission.end()
                                                        ? permission_entry->second
                                                        : base.override_permission;
    if (effective_permission == OverridePermission::Prohibited) {
      refuse(reasons::kOverrideProhibited,
             "mandatory delegated policy forbids local override of this subject");
      continue;
    }
    if (effective_permission == OverridePermission::AllowedWithAuthority) {
      if (input.authority == nullptr) {
        refuse(reasons::kOverrideUnauthorized,
               "override requires delegated override authority and no authority ledger is available");
        continue;
      }
      const RuleScope site_scope = RuleScope::for_sites({input.site});
      const AuthorityDecision decision = input.authority->evaluate(
          input.member, AuthorityAction::OverridePolicy, site_scope, entry.domain, input.now,
          input.membership);
      if (!decision.granted()) {
        refuse(reasons::kOverrideUnauthorized,
               std::string("delegated override authority is not valid: ") +
                   authority_outcome_name(decision.outcome));
        continue;
      }
      if (record->authority.is_nil() || record->authority != decision.grant) {
        refuse(reasons::kOverrideUnauthorized,
               "override does not name the delegated override authority it used");
        continue;
      }
    } else if (!record->authority.is_nil()) {
      // An override that cites a grant must cite a valid one, even where the rule itself permits
      // override: citing a revoked grant is not attributable authority.
      if (input.authority == nullptr) {
        refuse(reasons::kOverrideUnauthorized,
               "override cites an authority that cannot be verified without the authority ledger");
        continue;
      }
      const AuthorityDecision decision =
          input.authority->verify_chain(record->authority, input.now, input.membership);
      if (!decision.granted()) {
        refuse(reasons::kOverrideUnauthorized,
               std::string("cited override authority is not valid: ") +
                   authority_outcome_name(decision.outcome));
        continue;
      }
    }

    ++policy.overrides_applied;
    entry.state = EntryState::Overridden;
    entry.value = record->value;
    entry.applied_override = record->id;
    entry.override_authority = record->authority;
    entry.override_author = record->author;
    entry.override_reason = record->reason;
    entry.override_local_generation = record->local_generation;
    entry.reason_code = "local-override-applied";
    entry.detail = "local override " + record->id.to_string() + " by " + record->author;
    entry.explanation.insert(entry.explanation.begin(),
                             "override " + record->id.to_string() + " by " + record->author +
                                 " (local generation " +
                                 std::to_string(record->local_generation.value) + "): " +
                                 record->reason);

    receipt.kind = ReceiptKind::Overridden;
    receipt.reason_code = "local-override-applied";
    receipt.detail = "override applied by " + record->author + ": " + record->reason;
    receipt.bundle = entry.source_bundle;
    receipt.global_generation = entry.source_generation;
    receipt.rule = entry.source_rule;
    receipt.rule_digest = entry.source_rule_digest;
    receipt.bundle_digest = entry.source_bundle_digest;
    receipts.push_back(receipt);
  }

  // ---- 5. Deterministic ordering and digests --------------------------------------------
  std::sort(policy.entries.begin(), policy.entries.end(),
            [](const EffectiveEntry& a, const EffectiveEntry& b) {
              if (a.domain != b.domain) return a.domain < b.domain;
              return a.subject < b.subject;
            });
  std::sort(policy.conflicts.begin(), policy.conflicts.end(),
            [](const ConflictRecord& a, const ConflictRecord& b) {
              if (a.domain != b.domain) return a.domain < b.domain;
              if (a.subject != b.subject) return a.subject < b.subject;
              return a.id < b.id;
            });
  std::sort(receipts.begin(), receipts.end(), [](const Receipt& a, const Receipt& b) {
    const auto a_key = std::make_tuple(static_cast<std::uint8_t>(a.kind), a.bundle.to_string(),
                                       a.rule.to_string(), a.reason_code, a.detail);
    const auto b_key = std::make_tuple(static_cast<std::uint8_t>(b.kind), b.bundle.to_string(),
                                       b.rule.to_string(), b.reason_code, b.detail);
    return a_key < b_key;
  });
  std::uint64_t sequence = 0;
  for (Receipt& receipt : receipts) {
    receipt.sequence = SequenceNumber{++sequence};
    auto sealed = seal_receipt(receipt);
    if (!sealed.ok()) return Result<EffectivePolicy>::failure(sealed.error);
  }
  policy.receipts = std::move(receipts);

  auto digest = compute_effective_policy_digest(policy);
  if (!digest) return Result<EffectivePolicy>::failure(digest.error);
  policy.digest = *digest;
  return Result<EffectivePolicy>::success(std::move(policy));
}

}  // namespace gpf
namespace gpf {
namespace {

NegotiationOutcome negotiation_outcome_from_name(std::string_view name, NegotiationOutcome fallback) {
  if (name == "satisfied") return NegotiationOutcome::Satisfied;
  if (name == "unsupported") return NegotiationOutcome::UnsupportedCapability;
  if (name == "unknown") return NegotiationOutcome::UnknownCapability;
  if (name == "version-mismatch") return NegotiationOutcome::VersionMismatch;
  if (name == "catalog-stale") return NegotiationOutcome::CatalogStale;
  return fallback;
}

Result<Id128> id128_from_json(const JsonValue& value, const char* key, const char* prefix) {
  auto text = value.require_string(key);
  if (!text) return Result<Id128>::failure(text.error);
  const std::string expected(prefix);
  if (!has_prefix(*text, expected)) {
    return Result<Id128>::failure(ErrorCode::MalformedInput, "identity has the wrong kind",
                                  escape_preview(*text));
  }
  return Id128::from_hex(text->substr(expected.size()));
}

}  // namespace

Status validate_effective_policy(const EffectivePolicy& policy) {
  std::string previous;
  for (const EffectiveEntry& entry : policy.entries) {
    if (!is_valid_identifier(entry.domain) || !is_valid_identifier(entry.subject)) {
      return Status::failure(ErrorCode::InvalidArgument, "effective entry names an invalid subject",
                             entry.domain + "/" + entry.subject);
    }
    const std::string key = entry.domain + "/" + entry.subject;
    if (!previous.empty() && key <= previous) {
      return Status::failure(ErrorCode::InvalidArgument,
                             "effective policy entries are not in canonical order", key);
    }
    previous = key;
    if (entry_state_is_binding(entry.state) && entry.source_rule.is_nil()) {
      return Status::failure(ErrorCode::InvalidArgument,
                             "binding effective entry has no source rule", key);
    }
    if (entry.state == EntryState::Overridden && entry.applied_override.is_nil()) {
      return Status::failure(ErrorCode::InvalidArgument,
                             "overridden entry does not name the applied override", key);
    }
    if (entry.state == EntryState::Conflicted && entry.conflict.is_nil()) {
      return Status::failure(ErrorCode::InvalidArgument,
                             "conflicted entry does not name a conflict record", key);
    }
  }
  for (const ConflictRecord& record : policy.conflicts) {
    auto status = validate_conflict(record);
    if (!status.ok()) return status;
    auto computed = compute_conflict_digest(record);
    if (!computed) return Status::failure(computed.error);
    if (*computed != record.digest) {
      return Status::failure(ErrorCode::IntegrityFailure, "conflict digest does not match content",
                             record.id.to_string());
    }
  }
  for (const Receipt& receipt : policy.receipts) {
    auto status = validate_receipt(receipt);
    if (!status.ok()) return status;
    auto computed = compute_receipt_digest(receipt);
    if (!computed) return Status::failure(computed.error);
    if (*computed != receipt.digest) {
      return Status::failure(ErrorCode::IntegrityFailure, "receipt digest does not match content",
                             receipt.id.to_string());
    }
  }
  auto digest = compute_effective_policy_digest(policy);
  if (!digest) return Status::failure(digest.error);
  if (*digest != policy.digest) {
    return Status::failure(ErrorCode::IntegrityFailure,
                           "effective policy digest does not match its content", {});
  }
  return Status::success();
}

Result<Digest> compute_effective_policy_digest(const EffectivePolicy& policy) {
  CanonicalWriter writer;
  writer.tag("gpf.effective.v1");
  writer.id(policy.federation.value);
  writer.id(policy.member.value);
  writer.id(policy.site.value);
  writer.i64(policy.compiled_at.ms);
  writer.u64(policy.global_generation.value);
  writer.u64(policy.local_generation.value);
  writer.str(policy.runtime_version.to_string());
  writer.boolean(policy.partitioned);
  writer.u64(policy.rules_considered);
  writer.u64(policy.rules_applied);
  writer.u64(policy.rules_withheld);
  writer.u64(policy.rules_rejected);
  writer.u64(policy.rules_deferred);
  writer.u64(policy.rules_revoked);
  writer.u64(policy.rules_superseded);
  writer.u64(policy.overrides_applied);
  writer.u64(policy.overrides_refused);
  writer.u64(static_cast<std::uint64_t>(policy.entries.size()));
  for (const EffectiveEntry& entry : policy.entries) {
    writer.str(entry.domain);
    writer.str(entry.subject);
    writer.u8(static_cast<std::uint8_t>(entry.state));
    write_value(writer, entry.value);
    writer.u8(static_cast<std::uint8_t>(entry.effective_class));
    writer.id(entry.source_rule.value);
    writer.id(entry.source_bundle.value);
    writer.u64(entry.source_generation.value);
    writer.digest(entry.source_rule_digest);
    writer.digest(entry.source_bundle_digest);
    writer.id(entry.applied_override.value);
    writer.id(entry.override_authority.value);
    writer.str(entry.override_author);
    writer.str(entry.override_reason);
    writer.u64(entry.override_local_generation.value);
    writer.id(entry.conflict.value);
    writer.u8(static_cast<std::uint8_t>(entry.capability_outcome));
    writer.str(entry.capability_detail);
    writer.str(entry.reason_code);
    writer.str(entry.detail);
    writer.u64(static_cast<std::uint64_t>(entry.explanation.size()));
    for (const std::string& line : entry.explanation) writer.str(line);
  }
  writer.u64(static_cast<std::uint64_t>(policy.conflicts.size()));
  for (const ConflictRecord& record : policy.conflicts) writer.digest(record.digest);
  writer.u64(static_cast<std::uint64_t>(policy.receipts.size()));
  for (const Receipt& receipt : policy.receipts) {
    writer.digest(receipt.digest);
    writer.u64(receipt.sequence.value);
  }
  return Result<Digest>::success(writer.digest());
}

// ---------------------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------------------

JsonValue receipt_to_json(const Receipt& receipt) {
  return JsonValue::object({
      {"id", JsonValue::text(receipt.id.to_string())},
      {"federation", JsonValue::text(receipt.federation.to_string())},
      {"member", JsonValue::text(receipt.member.to_string())},
      {"site", JsonValue::text(receipt.site.to_string())},
      {"bundle", JsonValue::text(receipt.bundle.to_string())},
      {"global_generation", JsonValue::integer(static_cast<std::int64_t>(receipt.global_generation.value))},
      {"local_generation", JsonValue::integer(static_cast<std::int64_t>(receipt.local_generation.value))},
      {"kind", JsonValue::text(receipt_kind_name(receipt.kind))},
      {"reason_code", JsonValue::text(receipt.reason_code)},
      {"detail", JsonValue::text(receipt.detail)},
      {"rule", JsonValue::text(receipt.rule.to_string())},
      {"rule_digest", JsonValue::text(receipt.rule_digest.to_hex())},
      {"bundle_digest", JsonValue::text(receipt.bundle_digest.to_hex())},
      {"override_id", JsonValue::text(receipt.override_id.to_string())},
      {"at", JsonValue::integer(receipt.at.ms)},
      {"sequence", JsonValue::integer(static_cast<std::int64_t>(receipt.sequence.value))},
      {"digest", JsonValue::text(receipt.digest.to_hex())},
  });
}

Result<Receipt> receipt_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<Receipt>::failure(ErrorCode::MalformedInput, "receipt must be a json object", {});
  }
  Receipt receipt;
  auto id = id128_from_json(value, "id", ReceiptId::prefix());
  if (!id) return Result<Receipt>::failure(id.error);
  receipt.id.value = *id;
  auto federation = id128_from_json(value, "federation", FederationId::prefix());
  if (!federation) return Result<Receipt>::failure(federation.error);
  receipt.federation.value = *federation;
  auto member = id128_from_json(value, "member", MemberId::prefix());
  if (!member) return Result<Receipt>::failure(member.error);
  receipt.member.value = *member;
  auto site = id128_from_json(value, "site", SiteId::prefix());
  if (!site) return Result<Receipt>::failure(site.error);
  receipt.site.value = *site;
  auto bundle = id128_from_json(value, "bundle", PolicyBundleId::prefix());
  if (!bundle) return Result<Receipt>::failure(bundle.error);
  receipt.bundle.value = *bundle;
  auto global_generation = value.require_int_in_range("global_generation", 0, INT64_MAX);
  if (!global_generation) return Result<Receipt>::failure(global_generation.error);
  receipt.global_generation = Generation{static_cast<std::uint64_t>(*global_generation)};
  auto local_generation = value.require_int_in_range("local_generation", 0, INT64_MAX);
  if (!local_generation) return Result<Receipt>::failure(local_generation.error);
  receipt.local_generation = Generation{static_cast<std::uint64_t>(*local_generation)};
  auto kind = value.require_string("kind");
  if (!kind) return Result<Receipt>::failure(kind.error);
  auto parsed_kind = receipt_kind_from_name(*kind);
  if (!parsed_kind) return Result<Receipt>::failure(parsed_kind.error);
  receipt.kind = *parsed_kind;
  auto reason = value.require_string("reason_code");
  if (!reason) return Result<Receipt>::failure(reason.error);
  receipt.reason_code = *reason;
  auto detail = value.require_string("detail");
  if (!detail) return Result<Receipt>::failure(detail.error);
  receipt.detail = *detail;
  auto rule = id128_from_json(value, "rule", RuleId::prefix());
  if (!rule) return Result<Receipt>::failure(rule.error);
  receipt.rule.value = *rule;
  auto rule_digest = value.require_string("rule_digest");
  if (!rule_digest) return Result<Receipt>::failure(rule_digest.error);
  auto parsed_rule_digest = Digest::from_hex(*rule_digest);
  if (!parsed_rule_digest) return Result<Receipt>::failure(parsed_rule_digest.error);
  receipt.rule_digest = *parsed_rule_digest;
  auto bundle_digest = value.require_string("bundle_digest");
  if (!bundle_digest) return Result<Receipt>::failure(bundle_digest.error);
  auto parsed_bundle_digest = Digest::from_hex(*bundle_digest);
  if (!parsed_bundle_digest) return Result<Receipt>::failure(parsed_bundle_digest.error);
  receipt.bundle_digest = *parsed_bundle_digest;
  auto override_id = id128_from_json(value, "override_id", OverrideId::prefix());
  if (!override_id) return Result<Receipt>::failure(override_id.error);
  receipt.override_id.value = *override_id;
  auto at = value.require_int("at");
  if (!at) return Result<Receipt>::failure(at.error);
  receipt.at = Timestamp{*at};
  auto sequence = value.require_int_in_range("sequence", 0, INT64_MAX);
  if (!sequence) return Result<Receipt>::failure(sequence.error);
  receipt.sequence = SequenceNumber{static_cast<std::uint64_t>(*sequence)};
  auto digest = value.require_string("digest");
  if (!digest) return Result<Receipt>::failure(digest.error);
  auto parsed_digest = Digest::from_hex(*digest);
  if (!parsed_digest) return Result<Receipt>::failure(parsed_digest.error);
  receipt.digest = *parsed_digest;
  auto status = validate_receipt(receipt);
  if (!status.ok()) return Result<Receipt>::failure(status.error);
  auto computed = compute_receipt_digest(receipt);
  if (!computed) return Result<Receipt>::failure(computed.error);
  if (*computed != receipt.digest) {
    return Result<Receipt>::failure(ErrorCode::IntegrityFailure, "receipt digest does not match content");
  }
  return Result<Receipt>::success(std::move(receipt));
}

JsonValue conflict_to_json(const ConflictRecord& record) {
  JsonValue::Array participants;
  for (RuleId id : record.participants) participants.push_back(JsonValue::text(id.to_string()));
  JsonValue::Array bundles;
  for (PolicyBundleId id : record.bundles) bundles.push_back(JsonValue::text(id.to_string()));
  return JsonValue::object({
      {"id", JsonValue::text(record.id.to_string())},
      {"domain", JsonValue::text(record.domain)},
      {"subject", JsonValue::text(record.subject)},
      {"class", JsonValue::text(rule_class_name(record.rule_class))},
      {"participants", JsonValue::array(std::move(participants))},
      {"bundles", JsonValue::array(std::move(bundles))},
      {"reason_code", JsonValue::text(record.reason_code)},
      {"detail", JsonValue::text(record.detail)},
      {"detected_at", JsonValue::integer(record.detected_at.ms)},
      {"contained", JsonValue::boolean(record.contained)},
      {"digest", JsonValue::text(record.digest.to_hex())},
  });
}

Result<ConflictRecord> conflict_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<ConflictRecord>::failure(ErrorCode::MalformedInput, "conflict must be a json object", {});
  }
  ConflictRecord record;
  auto id = id128_from_json(value, "id", ConflictId::prefix());
  if (!id) return Result<ConflictRecord>::failure(id.error);
  record.id.value = *id;
  auto domain = value.require_string("domain");
  if (!domain) return Result<ConflictRecord>::failure(domain.error);
  record.domain = *domain;
  auto subject = value.require_string("subject");
  if (!subject) return Result<ConflictRecord>::failure(subject.error);
  record.subject = *subject;
  auto rule_class = value.require_string("class");
  if (!rule_class) return Result<ConflictRecord>::failure(rule_class.error);
  auto parsed_class = rule_class_from_name(*rule_class);
  if (!parsed_class) return Result<ConflictRecord>::failure(parsed_class.error);
  record.rule_class = *parsed_class;
  auto participants = value.require_array("participants");
  if (!participants) return Result<ConflictRecord>::failure(participants.error);
  for (const JsonValue& item : (*participants)->array_items()) {
    if (!item.is_string()) {
      return Result<ConflictRecord>::failure(ErrorCode::MalformedInput, "conflict participant is not a string", {});
    }
    auto parsed = RuleId::parse(item.as_string());
    if (!parsed) return Result<ConflictRecord>::failure(parsed.error);
    record.participants.push_back(*parsed);
  }
  auto bundles = value.require_array("bundles");
  if (!bundles) return Result<ConflictRecord>::failure(bundles.error);
  for (const JsonValue& item : (*bundles)->array_items()) {
    if (!item.is_string()) {
      return Result<ConflictRecord>::failure(ErrorCode::MalformedInput, "conflict bundle is not a string", {});
    }
    auto parsed = PolicyBundleId::parse(item.as_string());
    if (!parsed) return Result<ConflictRecord>::failure(parsed.error);
    record.bundles.push_back(*parsed);
  }
  auto reason = value.require_string("reason_code");
  if (!reason) return Result<ConflictRecord>::failure(reason.error);
  record.reason_code = *reason;
  auto detail = value.require_string("detail");
  if (!detail) return Result<ConflictRecord>::failure(detail.error);
  record.detail = *detail;
  auto detected_at = value.require_int("detected_at");
  if (!detected_at) return Result<ConflictRecord>::failure(detected_at.error);
  record.detected_at = Timestamp{*detected_at};
  auto contained = value.require_bool("contained");
  if (!contained) return Result<ConflictRecord>::failure(contained.error);
  record.contained = *contained;
  auto digest = value.require_string("digest");
  if (!digest) return Result<ConflictRecord>::failure(digest.error);
  auto parsed_digest = Digest::from_hex(*digest);
  if (!parsed_digest) return Result<ConflictRecord>::failure(parsed_digest.error);
  record.digest = *parsed_digest;
  auto status = validate_conflict(record);
  if (!status.ok()) return Result<ConflictRecord>::failure(status.error);
  auto computed = compute_conflict_digest(record);
  if (!computed) return Result<ConflictRecord>::failure(computed.error);
  if (*computed != record.digest) {
    return Result<ConflictRecord>::failure(ErrorCode::IntegrityFailure, "conflict digest does not match content");
  }
  return Result<ConflictRecord>::success(std::move(record));
}

JsonValue entry_to_json(const EffectiveEntry& entry) {
  JsonValue::Array explanation;
  for (const std::string& line : entry.explanation) explanation.push_back(JsonValue::text(line));
  return JsonValue::object({
      {"domain", JsonValue::text(entry.domain)},
      {"subject", JsonValue::text(entry.subject)},
      {"state", JsonValue::text(entry_state_name(entry.state))},
      {"value", setting_value_to_json(entry.value)},
      {"class", JsonValue::text(rule_class_name(entry.effective_class))},
      {"source_rule", JsonValue::text(entry.source_rule.to_string())},
      {"source_bundle", JsonValue::text(entry.source_bundle.to_string())},
      {"source_generation", JsonValue::integer(static_cast<std::int64_t>(entry.source_generation.value))},
      {"source_rule_digest", JsonValue::text(entry.source_rule_digest.to_hex())},
      {"source_bundle_digest", JsonValue::text(entry.source_bundle_digest.to_hex())},
      {"applied_override", JsonValue::text(entry.applied_override.to_string())},
      {"override_authority", JsonValue::text(entry.override_authority.to_string())},
      {"override_author", JsonValue::text(entry.override_author)},
      {"override_reason", JsonValue::text(entry.override_reason)},
      {"override_local_generation",
       JsonValue::integer(static_cast<std::int64_t>(entry.override_local_generation.value))},
      {"conflict", JsonValue::text(entry.conflict.to_string())},
      {"capability_outcome", JsonValue::text(negotiation_outcome_name(entry.capability_outcome))},
      {"capability_detail", JsonValue::text(entry.capability_detail)},
      {"reason_code", JsonValue::text(entry.reason_code)},
      {"detail", JsonValue::text(entry.detail)},
      {"explanation", JsonValue::array(std::move(explanation))},
  });
}

Result<EffectiveEntry> entry_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<EffectiveEntry>::failure(ErrorCode::MalformedInput, "entry must be a json object", {});
  }
  EffectiveEntry entry;
  auto domain = value.require_string("domain");
  if (!domain) return Result<EffectiveEntry>::failure(domain.error);
  entry.domain = *domain;
  auto subject = value.require_string("subject");
  if (!subject) return Result<EffectiveEntry>::failure(subject.error);
  entry.subject = *subject;
  auto state = value.require_string("state");
  if (!state) return Result<EffectiveEntry>::failure(state.error);
  auto parsed_state = entry_state_from_name(*state);
  if (!parsed_state) return Result<EffectiveEntry>::failure(parsed_state.error);
  entry.state = *parsed_state;
  auto setting = value.require_object("value");
  if (!setting) return Result<EffectiveEntry>::failure(setting.error);
  auto parsed_value = setting_value_from_json(**setting);
  if (!parsed_value) return Result<EffectiveEntry>::failure(parsed_value.error);
  entry.value = *parsed_value;
  auto rule_class = value.require_string("class");
  if (!rule_class) return Result<EffectiveEntry>::failure(rule_class.error);
  auto parsed_class = rule_class_from_name(*rule_class);
  if (!parsed_class) return Result<EffectiveEntry>::failure(parsed_class.error);
  entry.effective_class = *parsed_class;
  auto source_rule = id128_from_json(value, "source_rule", RuleId::prefix());
  if (!source_rule) return Result<EffectiveEntry>::failure(source_rule.error);
  entry.source_rule.value = *source_rule;
  auto source_bundle = id128_from_json(value, "source_bundle", PolicyBundleId::prefix());
  if (!source_bundle) return Result<EffectiveEntry>::failure(source_bundle.error);
  entry.source_bundle.value = *source_bundle;
  auto source_generation = value.require_int_in_range("source_generation", 0, INT64_MAX);
  if (!source_generation) return Result<EffectiveEntry>::failure(source_generation.error);
  entry.source_generation = Generation{static_cast<std::uint64_t>(*source_generation)};
  auto rule_digest = value.require_string("source_rule_digest");
  if (!rule_digest) return Result<EffectiveEntry>::failure(rule_digest.error);
  auto parsed_rule_digest = Digest::from_hex(*rule_digest);
  if (!parsed_rule_digest) return Result<EffectiveEntry>::failure(parsed_rule_digest.error);
  entry.source_rule_digest = *parsed_rule_digest;
  auto bundle_digest = value.require_string("source_bundle_digest");
  if (!bundle_digest) return Result<EffectiveEntry>::failure(bundle_digest.error);
  auto parsed_bundle_digest = Digest::from_hex(*bundle_digest);
  if (!parsed_bundle_digest) return Result<EffectiveEntry>::failure(parsed_bundle_digest.error);
  entry.source_bundle_digest = *parsed_bundle_digest;
  auto applied_override = id128_from_json(value, "applied_override", OverrideId::prefix());
  if (!applied_override) return Result<EffectiveEntry>::failure(applied_override.error);
  entry.applied_override.value = *applied_override;
  auto override_authority = id128_from_json(value, "override_authority", GrantId::prefix());
  if (!override_authority) return Result<EffectiveEntry>::failure(override_authority.error);
  entry.override_authority.value = *override_authority;
  auto override_author = value.require_string("override_author");
  if (!override_author) return Result<EffectiveEntry>::failure(override_author.error);
  entry.override_author = *override_author;
  auto override_reason = value.require_string("override_reason");
  if (!override_reason) return Result<EffectiveEntry>::failure(override_reason.error);
  entry.override_reason = *override_reason;
  auto override_generation = value.require_int_in_range("override_local_generation", 0, INT64_MAX);
  if (!override_generation) return Result<EffectiveEntry>::failure(override_generation.error);
  entry.override_local_generation = Generation{static_cast<std::uint64_t>(*override_generation)};
  auto conflict = id128_from_json(value, "conflict", ConflictId::prefix());
  if (!conflict) return Result<EffectiveEntry>::failure(conflict.error);
  entry.conflict.value = *conflict;
  auto capability_outcome = value.require_string("capability_outcome");
  if (!capability_outcome) return Result<EffectiveEntry>::failure(capability_outcome.error);
  entry.capability_outcome =
      negotiation_outcome_from_name(*capability_outcome, NegotiationOutcome::Satisfied);
  auto capability_detail = value.require_string("capability_detail");
  if (!capability_detail) return Result<EffectiveEntry>::failure(capability_detail.error);
  entry.capability_detail = *capability_detail;
  auto reason = value.require_string("reason_code");
  if (!reason) return Result<EffectiveEntry>::failure(reason.error);
  entry.reason_code = *reason;
  auto detail = value.require_string("detail");
  if (!detail) return Result<EffectiveEntry>::failure(detail.error);
  entry.detail = *detail;
  auto explanation = value.require_array("explanation");
  if (!explanation) return Result<EffectiveEntry>::failure(explanation.error);
  for (const JsonValue& item : (*explanation)->array_items()) {
    if (!item.is_string()) {
      return Result<EffectiveEntry>::failure(ErrorCode::MalformedInput, "explanation line is not a string", {});
    }
    entry.explanation.push_back(item.as_string());
  }
  return Result<EffectiveEntry>::success(std::move(entry));
}

JsonValue effective_policy_to_json(const EffectivePolicy& policy) {
  JsonValue::Array entries;
  for (const EffectiveEntry& entry : policy.entries) entries.push_back(entry_to_json(entry));
  JsonValue::Array conflicts;
  for (const ConflictRecord& record : policy.conflicts) conflicts.push_back(conflict_to_json(record));
  JsonValue::Array receipts;
  for (const Receipt& receipt : policy.receipts) receipts.push_back(receipt_to_json(receipt));
  return JsonValue::object({
      {"federation", JsonValue::text(policy.federation.to_string())},
      {"member", JsonValue::text(policy.member.to_string())},
      {"site", JsonValue::text(policy.site.to_string())},
      {"compiled_at", JsonValue::integer(policy.compiled_at.ms)},
      {"global_generation", JsonValue::integer(static_cast<std::int64_t>(policy.global_generation.value))},
      {"local_generation", JsonValue::integer(static_cast<std::int64_t>(policy.local_generation.value))},
      {"runtime_version", JsonValue::text(policy.runtime_version.to_string())},
      {"partitioned", JsonValue::boolean(policy.partitioned)},
      {"rules_considered", JsonValue::integer(static_cast<std::int64_t>(policy.rules_considered))},
      {"rules_applied", JsonValue::integer(static_cast<std::int64_t>(policy.rules_applied))},
      {"rules_withheld", JsonValue::integer(static_cast<std::int64_t>(policy.rules_withheld))},
      {"rules_rejected", JsonValue::integer(static_cast<std::int64_t>(policy.rules_rejected))},
      {"rules_deferred", JsonValue::integer(static_cast<std::int64_t>(policy.rules_deferred))},
      {"rules_revoked", JsonValue::integer(static_cast<std::int64_t>(policy.rules_revoked))},
      {"rules_superseded", JsonValue::integer(static_cast<std::int64_t>(policy.rules_superseded))},
      {"overrides_applied", JsonValue::integer(static_cast<std::int64_t>(policy.overrides_applied))},
      {"overrides_refused", JsonValue::integer(static_cast<std::int64_t>(policy.overrides_refused))},
      {"entries", JsonValue::array(std::move(entries))},
      {"conflicts", JsonValue::array(std::move(conflicts))},
      {"receipts", JsonValue::array(std::move(receipts))},
      {"digest", JsonValue::text(policy.digest.to_hex())},
  });
}

Result<EffectivePolicy> effective_policy_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<EffectivePolicy>::failure(ErrorCode::MalformedInput,
                                            "effective policy must be a json object", {});
  }
  EffectivePolicy policy;
  auto federation = value.require_string("federation");
  if (!federation) return Result<EffectivePolicy>::failure(federation.error);
  auto parsed_federation = FederationId::parse(*federation);
  if (!parsed_federation) return Result<EffectivePolicy>::failure(parsed_federation.error);
  policy.federation = *parsed_federation;
  auto member = value.require_string("member");
  if (!member) return Result<EffectivePolicy>::failure(member.error);
  auto parsed_member = MemberId::parse(*member);
  if (!parsed_member) return Result<EffectivePolicy>::failure(parsed_member.error);
  policy.member = *parsed_member;
  auto site = value.require_string("site");
  if (!site) return Result<EffectivePolicy>::failure(site.error);
  auto parsed_site = SiteId::parse(*site);
  if (!parsed_site) return Result<EffectivePolicy>::failure(parsed_site.error);
  policy.site = *parsed_site;
  auto compiled_at = value.require_int("compiled_at");
  if (!compiled_at) return Result<EffectivePolicy>::failure(compiled_at.error);
  policy.compiled_at = Timestamp{*compiled_at};
  auto global_generation = value.require_int_in_range("global_generation", 0, INT64_MAX);
  if (!global_generation) return Result<EffectivePolicy>::failure(global_generation.error);
  policy.global_generation = Generation{static_cast<std::uint64_t>(*global_generation)};
  auto local_generation = value.require_int_in_range("local_generation", 0, INT64_MAX);
  if (!local_generation) return Result<EffectivePolicy>::failure(local_generation.error);
  policy.local_generation = Generation{static_cast<std::uint64_t>(*local_generation)};
  auto runtime_version = value.require_string("runtime_version");
  if (!runtime_version) return Result<EffectivePolicy>::failure(runtime_version.error);
  auto parsed_runtime = SemanticVersion::parse(*runtime_version);
  if (!parsed_runtime) return Result<EffectivePolicy>::failure(parsed_runtime.error);
  policy.runtime_version = *parsed_runtime;
  auto partitioned = value.require_bool("partitioned");
  if (!partitioned) return Result<EffectivePolicy>::failure(partitioned.error);
  policy.partitioned = *partitioned;
  auto entries = value.require_array("entries");
  if (!entries) return Result<EffectivePolicy>::failure(entries.error);
  for (const JsonValue& item : (*entries)->array_items()) {
    auto entry = entry_from_json(item);
    if (!entry) return Result<EffectivePolicy>::failure(entry.error);
    policy.entries.push_back(std::move(*entry.value));
  }
  auto conflicts = value.require_array("conflicts");
  if (!conflicts) return Result<EffectivePolicy>::failure(conflicts.error);
  for (const JsonValue& item : (*conflicts)->array_items()) {
    auto record = conflict_from_json(item);
    if (!record) return Result<EffectivePolicy>::failure(record.error);
    policy.conflicts.push_back(std::move(*record.value));
  }
  auto receipts = value.require_array("receipts");
  if (!receipts) return Result<EffectivePolicy>::failure(receipts.error);
  for (const JsonValue& item : (*receipts)->array_items()) {
    auto receipt = receipt_from_json(item);
    if (!receipt) return Result<EffectivePolicy>::failure(receipt.error);
    policy.receipts.push_back(std::move(*receipt.value));
  }
  const auto read_count = [&](const char* key, std::size_t& target) -> Status {
    auto raw = value.require_int_in_range(key, 0, INT64_MAX);
    if (!raw) return Status::failure(raw.error);
    target = static_cast<std::size_t>(*raw);
    return Status::success();
  };
  Status count_status = read_count("rules_considered", policy.rules_considered);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("rules_applied", policy.rules_applied);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("rules_withheld", policy.rules_withheld);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("rules_rejected", policy.rules_rejected);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("rules_deferred", policy.rules_deferred);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("rules_revoked", policy.rules_revoked);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("rules_superseded", policy.rules_superseded);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("overrides_applied", policy.overrides_applied);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  count_status = read_count("overrides_refused", policy.overrides_refused);
  if (!count_status.ok()) return Result<EffectivePolicy>::failure(count_status.error);
  auto digest = value.require_string("digest");
  if (!digest) return Result<EffectivePolicy>::failure(digest.error);
  auto parsed_digest = Digest::from_hex(*digest);
  if (!parsed_digest) return Result<EffectivePolicy>::failure(parsed_digest.error);
  policy.digest = *parsed_digest;
  auto status = validate_effective_policy(policy);
  if (!status.ok()) return Result<EffectivePolicy>::failure(status.error);
  return Result<EffectivePolicy>::success(std::move(policy));
}

}  // namespace gpf
