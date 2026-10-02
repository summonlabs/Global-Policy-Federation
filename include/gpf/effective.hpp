#pragma once
// Global Policy Federation — effective policy compilation, conflict containment and receipts.
//
// Compilation is a pure function of its inputs: the same accepted bundles, overrides, capability
// view, authority ledger and clock produce byte-identical output on any site. Nothing here
// reaches the network, the disk, or another runtime's internals.
//
// The compiled result never collapses the distinctions this boundary exists to preserve:
// propagation is not acceptance, acceptance is not activation, a local override is not a
// violation, incompatibility is not transient unavailability, stale is not revoked, and unknown
// is not unsupported.

#include "gpf/authority.hpp"
#include "gpf/base.hpp"
#include "gpf/codec.hpp"
#include "gpf/policy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gpf {

// ---------------------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------------------

// Receipts are the durable evidence trail. Acceptance happens in the site runtime, activation in
// the compiler; both are recorded separately so that propagated-but-not-accepted and
// accepted-but-not-applied stay distinguishable.
enum class ReceiptKind : std::uint8_t {
  Accepted = 0,
  Applied = 1,
  Rejected = 2,
  Overridden = 3,
  Revoked = 4,
  Deferred = 5,
  Superseded = 6,
  ConflictRecorded = 7,
  Withheld = 8,
};

const char* receipt_kind_name(ReceiptKind value) noexcept;
Result<ReceiptKind> receipt_kind_from_name(std::string_view name);

// Stable symbolic reason codes shared by receipts, explanations and logs.
namespace reasons {
inline constexpr const char* kCapabilityUnsatisfied = "capability-unsatisfied";
inline constexpr const char* kCapabilityUnknown = "capability-unknown";
inline constexpr const char* kCatalogStale = "capability-catalog-stale";
inline constexpr const char* kOverrideProhibited = "override-prohibited";
inline constexpr const char* kOverrideUnauthorized = "override-unauthorized";
inline constexpr const char* kOverrideNotApplicable = "override-not-applicable";
inline constexpr const char* kOverrideSuperseded = "override-superseded";
inline constexpr const char* kOverrideWithoutBase = "override-without-base";
inline constexpr const char* kPolicyExpired = "policy-expired";
inline constexpr const char* kPolicyNotYetEffective = "policy-not-yet-effective";
inline constexpr const char* kPolicyWithheldStale = "policy-withheld-stale";
inline constexpr const char* kPolicyLastKnownValid = "policy-last-known-valid";
inline constexpr const char* kPolicyRevoked = "policy-revoked";
inline constexpr const char* kRuleRevoked = "rule-revoked";
inline constexpr const char* kContradictoryMandatory = "contradictory-mandatory-rules";
inline constexpr const char* kContradictoryDefault = "contradictory-default-rules";
inline constexpr const char* kContradictoryAdvisory = "contradictory-advisory-rules";
inline constexpr const char* kAdvisoryOnly = "advisory-only";
inline constexpr const char* kRuntimeIncompatible = "runtime-version-incompatible";
inline constexpr const char* kCompatibilityMismatch = "compatibility-digest-mismatch";
inline constexpr const char* kAuthorityDenied = "authority-denied";
inline constexpr const char* kGenerationSuperseded = "policy-generation-superseded";
inline constexpr const char* kPolicyBlocked = "policy-not-usable";
}  // namespace reasons

struct Receipt {
  ReceiptId id;
  FederationId federation;
  MemberId member;
  SiteId site;
  PolicyBundleId bundle;
  Generation global_generation{};
  Generation local_generation{};
  ReceiptKind kind{ReceiptKind::Applied};
  std::string reason_code;
  std::string detail;
  RuleId rule;
  Digest rule_digest{};
  Digest bundle_digest{};
  OverrideId override_id;
  Timestamp at{};
  SequenceNumber sequence{};  // assigned by the site runtime when the receipt is persisted
  Digest digest{};

  friend bool operator==(const Receipt&, const Receipt&) noexcept = default;
};

Status validate_receipt(const Receipt& receipt);
Result<Digest> compute_receipt_digest(const Receipt& receipt);
Status seal_receipt(Receipt& receipt);
// Receipts carry derived identities: replaying the same decision yields the same identity, so a
// duplicated delivery cannot create a second, contradictory receipt.
ReceiptId derive_receipt_id(const Receipt& receipt);

JsonValue receipt_to_json(const Receipt& receipt);
Result<Receipt> receipt_from_json(const JsonValue& value);
// ---------------------------------------------------------------------------------------
// Conflicts
// ---------------------------------------------------------------------------------------

struct ConflictRecord {
  ConflictId id;
  std::string domain;
  std::string subject;
  std::vector<RuleId> participants;     // sorted, deduplicated
  std::vector<PolicyBundleId> bundles;  // sorted, deduplicated
  RuleClass rule_class{RuleClass::Mandatory};
  std::string reason_code;
  std::string detail;
  Timestamp detected_at{};
  // Containment: the conflict is confined to this subject. Everything else in the domain still
  // compiles, and no participant is reordered to invent a winner.
  bool contained{true};
  Digest digest{};

  friend bool operator==(const ConflictRecord&, const ConflictRecord&) noexcept = default;
};

Status validate_conflict(const ConflictRecord& record);
Result<Digest> compute_conflict_digest(const ConflictRecord& record);
Status seal_conflict(ConflictRecord& record);
ConflictId derive_conflict_id(const ConflictRecord& record);

JsonValue conflict_to_json(const ConflictRecord& record);
Result<ConflictRecord> conflict_from_json(const JsonValue& value);

// ---------------------------------------------------------------------------------------
// Effective entries
// ---------------------------------------------------------------------------------------

enum class EntryState : std::uint8_t {
  Absent = 0,          // nothing addresses this subject
  Active = 1,          // binding and current
  Overridden = 2,      // binding, decided by an accepted local override
  LastKnownValid = 3,  // usable only because staleness policy explicitly permits it
  Advisory = 4,        // informational only: advisory policy never binds
  Conflicted = 5,      // authoritative sources disagree and precedence cannot decide
  Withheld = 6,        // policy exists but may not be used (stale, expired, not yet effective)
  Revoked = 7,         // the governing policy was revoked
  Incompatible = 8,    // capability prerequisites are not met
  Indeterminate = 9,   // deferral: capability unknown, catalog stale, or partition blocks resolution
};

const char* entry_state_name(EntryState value) noexcept;
Result<EntryState> entry_state_from_name(std::string_view name);
bool entry_state_is_binding(EntryState state) noexcept;

struct EffectiveEntry {
  std::string domain;
  std::string subject;
  EntryState state{EntryState::Absent};
  SettingValue value{};
  RuleClass effective_class{RuleClass::Default};

  RuleId source_rule;
  PolicyBundleId source_bundle;
  Generation source_generation{};
  Digest source_rule_digest{};
  Digest source_bundle_digest{};

  OverrideId applied_override;
  GrantId override_authority;
  std::string override_author;
  std::string override_reason;
  Generation override_local_generation{};

  ConflictId conflict;
  NegotiationOutcome capability_outcome{NegotiationOutcome::Satisfied};
  std::string capability_detail;
  std::string reason_code;
  std::string detail;
  // Ordered provenance: newest decision first, then the underlying policy.
  std::vector<std::string> explanation;

  friend bool operator==(const EffectiveEntry&, const EffectiveEntry&) noexcept = default;
};

JsonValue entry_to_json(const EffectiveEntry& entry);
Result<EffectiveEntry> entry_from_json(const JsonValue& value);
// ---------------------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------------------

struct EffectivePolicyInput {
  FederationId federation;
  MemberId member;
  SiteId site;
  Timestamp now{};

  // Policy the site has accepted from the federation, in any order.
  std::vector<PolicyBundle> accepted_bundles;
  // Policy the site authored for itself. Local bundles never go stale and are never subject to
  // global revocation, but they are still validated and digested like any other policy.
  std::vector<PolicyBundle> local_bundles;
  std::vector<LocalOverride> overrides;
  SiteCapabilitySnapshot capabilities;
  CapabilityCatalog capability_catalog;
  SemanticVersion runtime_version{};  // the site's own runtime capability surface

  // Authority ledger used to decide override rights. Absent means no delegated authority is
  // available, which refuses authority-requiring overrides instead of assuming them.
  const AuthorityLedger* authority{nullptr};
  // Membership truth consumed from the federation, used only to resolve member-scoped delegated
  // authority against this site. It never grants anything by itself.
  const MembershipBinding* membership{nullptr};

  // Partition state. Partitioned means the site is not currently in contact with the
  // federation; last_contact_at is the last verified synchronization instant.
  bool partitioned{false};
  Timestamp last_contact_at{};

  // Integrity re-verification of every input bundle on every compilation. Leave this on unless
  // the caller has already verified the bundles on the way in and holds them behind that
  // verification: a runtime verifies at acceptance and again when replaying durable state, so the
  // compiler can validate structure only. Turning it off is a trust decision, not a speed dial.
  bool verify_bundle_integrity{true};

  // Bounds. The compiler refuses to exceed them rather than degrading silently.
  std::size_t max_rules = limits::kMaxRulesPerCompilation;
  std::size_t max_conflicts = limits::kMaxConflictRecords;
};

struct EffectivePolicy {
  FederationId federation;
  MemberId member;
  SiteId site;
  Timestamp compiled_at{};
  Generation global_generation{};  // newest global generation represented in the result
  Generation local_generation{};
  SemanticVersion runtime_version{};

  std::vector<EffectiveEntry> entries;    // sorted by domain then subject
  std::vector<ConflictRecord> conflicts;  // sorted by domain, subject, identity
  std::vector<Receipt> receipts;          // deterministically ordered

  bool partitioned{false};
  std::size_t rules_considered{0};
  std::size_t rules_applied{0};
  std::size_t rules_withheld{0};
  std::size_t rules_rejected{0};
  std::size_t rules_deferred{0};
  std::size_t rules_revoked{0};
  std::size_t rules_superseded{0};
  std::size_t overrides_applied{0};
  std::size_t overrides_refused{0};
  Digest digest{};

  const EffectiveEntry* find(std::string_view domain, std::string_view subject) const noexcept;
};

Result<EffectivePolicy> compile_effective_policy(const EffectivePolicyInput& input);

// Explains one subject. Returns an entry in state Absent when nothing addresses it, which is a
// different answer from conflicted or withheld.
EffectiveEntry explain_subject(const EffectivePolicy& policy, std::string_view domain,
                               std::string_view subject);

Status validate_effective_policy(const EffectivePolicy& policy);
Result<Digest> compute_effective_policy_digest(const EffectivePolicy& policy);

JsonValue effective_policy_to_json(const EffectivePolicy& policy);
Result<EffectivePolicy> effective_policy_from_json(const JsonValue& value);

}  // namespace gpf
