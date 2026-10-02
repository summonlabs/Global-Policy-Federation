#pragma once
// Global Policy Federation — policy data model.
//
// A policy bundle is authored content published by one federation member under an explicit
// delegated authority. A rule is the smallest authoritative unit: it addresses one subject in
// one conflict domain, carries one typed value, and declares exactly what may override it.
//
// Nothing in this header performs I/O, holds locks, or consults the clock.

#include "gpf/base.hpp"
#include "gpf/codec.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gpf {

// ---------------------------------------------------------------------------------------
// Semantic version of a rule or capability surface
// ---------------------------------------------------------------------------------------

struct SemanticVersion {
  std::uint32_t major{0};
  std::uint32_t minor{0};
  std::uint32_t patch{0};

  std::string to_string() const;
  static Result<SemanticVersion> parse(std::string_view text);

  // Compatibility is declared, not inferred: a consumer that implements major X can consume
  // any version with the same major and a minor not newer than its own.
  bool backward_compatible_with(const SemanticVersion& consumer) const noexcept;

  friend bool operator==(const SemanticVersion&, const SemanticVersion&) noexcept = default;
  friend std::strong_ordering operator<=>(const SemanticVersion&, const SemanticVersion&) noexcept = default;
};

// ---------------------------------------------------------------------------------------
// Rule classification and applicability
// ---------------------------------------------------------------------------------------

// Mandatory global policy is binding where delegated. Default policy is a starting point that
// local sovereignty may replace. Advisory policy never becomes binding.
enum class RuleClass : std::uint8_t {
  Advisory = 0,
  Default = 1,
  Mandatory = 2,
};

const char* rule_class_name(RuleClass value) noexcept;
Result<RuleClass> rule_class_from_name(std::string_view name);

enum class ScopeLevel : std::uint8_t {
  Federation = 0,
  Member = 1,
  Site = 2,
};

const char* scope_level_name(ScopeLevel value) noexcept;
Result<ScopeLevel> scope_level_from_name(std::string_view name);

// Where a bundle or rule applies. An empty target list on a Member/Site scope is invalid:
// a scope with no target would silently mean "everyone", which is exactly the implicit
// authority this boundary refuses.
struct RuleScope {
  ScopeLevel level{ScopeLevel::Federation};
  std::vector<MemberId> members;
  std::vector<SiteId> sites;

  static RuleScope federation();
  static RuleScope for_members(std::vector<MemberId> members);
  static RuleScope for_sites(std::vector<SiteId> sites);

  // 0 = federation-wide, 1 = member scoped, 2 = site scoped.
  std::uint8_t specificity() const noexcept { return static_cast<std::uint8_t>(level); }
  bool is_federation_wide() const noexcept { return level == ScopeLevel::Federation; }

  friend bool operator==(const RuleScope&, const RuleScope&) noexcept = default;
};

bool scope_contains_site(const RuleScope& scope, MemberId member, SiteId site) noexcept;

// Membership binding: which sites a member owns, as published by federation membership truth.
// This boundary consumes that truth explicitly; it never infers it, and it never treats
// membership itself as authority.
struct MembershipBinding {
  std::vector<std::pair<MemberId, SiteId>> entries;

  bool contains(MemberId member, SiteId site) const noexcept;
  bool binds_site_to_any(const std::vector<MemberId>& members, SiteId site) const noexcept;
  friend bool operator==(const MembershipBinding&, const MembershipBinding&) noexcept = default;
};

Status validate_membership_binding(const MembershipBinding& binding);

// True when every site selected by 'inner' is also selected by 'outer'. A grant can only be
// narrowed, never widened, which is what keeps delegation from inventing authority.
//
// Resolving a member-scoped outer against a site-scoped inner requires the membership binding:
// without it the answer is "cannot be established", which is reported as containment failure
// rather than assumed.
bool scope_contains_scope(const RuleScope& outer, const RuleScope& inner,
                          const MembershipBinding* binding = nullptr);

Status validate_scope(const RuleScope& scope);

// A typed setting value. Types are never coerced: an integer rule and a text rule with the same
// subject are contradictory, not convertible.
struct SettingValue {
  enum class Type : std::uint8_t { Unset = 0, Boolean = 1, Integer = 2, Text = 3 };

  Type type{Type::Unset};
  bool boolean{false};
  std::int64_t integer{0};
  std::string text;

  static SettingValue unset();
  static SettingValue boolean_value(bool value);
  static SettingValue integer_value(std::int64_t value);
  static SettingValue text_value(std::string value);

  const char* type_name() const noexcept;
  bool is_set() const noexcept { return type != Type::Unset; }
  std::string to_display_string() const;

  friend bool operator==(const SettingValue&, const SettingValue&) noexcept;
};

// Explicit, declared override rights. Absence of permission is refusal, never negotiation.
enum class OverridePermission : std::uint8_t {
  Prohibited = 0,            // local override is refused deterministically
  AllowedWithAuthority = 1,  // requires an unexpired delegated override authority in scope
  Allowed = 2,               // local override permitted, still explicit/attributable/durable
};

const char* override_permission_name(OverridePermission value) noexcept;
Result<OverridePermission> override_permission_from_name(std::string_view name);

// Behavior when the publishing federation cannot be reached. RequireFresh withholds policy
// instead of silently keeping it; AllowLastKnownValid keeps the last accepted generation for a
// bounded window and reports it as last-known-valid rather than current.
struct StalenessPolicy {
  enum class Mode : std::uint8_t { RequireFresh = 0, AllowLastKnownValid = 1 };

  Mode mode{Mode::RequireFresh};
  Millis max_staleness_ms{0};

  static StalenessPolicy require_fresh();
  static StalenessPolicy allow_last_known_valid(Millis max_staleness_ms);
  friend bool operator==(const StalenessPolicy&, const StalenessPolicy&) noexcept = default;
};

const char* staleness_mode_name(StalenessPolicy::Mode value) noexcept;
Result<StalenessPolicy::Mode> staleness_mode_from_name(std::string_view name);

// Capability prerequisites. "Unknown" and "unsupported" stay distinct: a site that has never
// been told about a capability is deferred, a site that reports it does not implement it is
// refused.
struct CapabilityRequirement {
  std::string capability;
  SemanticVersion min_version{};
  bool optional{false};

  friend bool operator==(const CapabilityRequirement&, const CapabilityRequirement&) noexcept = default;
};

Status validate_capability_requirement(const CapabilityRequirement& requirement);

// ---------------------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------------------

struct Rule {
  RuleId id;
  SemanticVersion version{};
  std::string domain;   // conflict domain identifier
  std::string subject;  // setting addressed inside the domain
  RuleClass rule_class{RuleClass::Default};

  // Honored only between mandatory rules in the same domain, class and scope level. It never
  // orders rules across different sites or across arrival order.
  std::uint32_t precedence{0};

  RuleScope scope{};
  SettingValue value{};
  std::vector<CapabilityRequirement> capability_requirements{};
  OverridePermission override_permission{OverridePermission::Allowed};
  StalenessPolicy staleness{};
  Timestamp effective_from{};
  Timestamp expires_at{};  // zero means "no declared expiry"
  std::string rationale;

  std::string key() const;  // domain then subject, separated by a slash
  bool is_expired_at(Timestamp now) const noexcept;
  bool is_effective_at(Timestamp now) const noexcept;
  bool applies_to(MemberId member, SiteId site) const noexcept;
};

Status validate_rule(const Rule& rule);
Result<Digest> compute_rule_digest(const Rule& rule);

// ---------------------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------------------

// A provenance chain entry records who acted, under which delegated authority, on top of which
// previous entry. The chain is verified, not trusted.
struct ProvenanceEntry {
  std::string actor;
  MemberId member;
  GrantId grant;            // may be nil only for the federation root authority
  Epoch authority_epoch{};
  Generation generation{};  // generation of the publishing sequence this entry belongs to
  Timestamp at{};
  Digest previous{};     // digest of the preceding entry; nil for the chain head
  Digest entry_digest{};  // computed over the fields above plus the note
  std::string note;
};

Result<Digest> compute_provenance_digest(const ProvenanceEntry& entry);
Status validate_provenance_chain(const std::vector<ProvenanceEntry>& chain);

// ---------------------------------------------------------------------------------------
// Policy bundle
// ---------------------------------------------------------------------------------------

struct PolicyBundle {
  PolicyBundleId id;
  FederationId federation;
  Generation global_generation{};  // monotonic per federation issuer
  MemberId issuer_member;
  RuleScope scope{};
  Timestamp issued_at{};
  Timestamp effective_from{};
  Timestamp expires_at{};  // zero means "no declared expiry"

  // Compatibility surface. A site first compares its own view of the compatibility digest and
  // only then walks the rules.
  SemanticVersion required_runtime{};
  Generation capability_catalog_generation{};
  StalenessPolicy staleness{};

  std::vector<Rule> rules;
  std::vector<ProvenanceEntry> provenance;

  Digest integrity_digest{};      // computed and verified, never authored
  Digest compatibility_digest{};  // computed and verified, never authored
};

// Canonical ordering inside a bundle: rules sorted by identity, scope targets sorted and
// deduplicated. Normalization is idempotent and is required before sealing.
void normalize_bundle(PolicyBundle& bundle);

Status validate_bundle(const PolicyBundle& bundle);
Status seal_bundle(PolicyBundle& bundle);
Status verify_bundle(const PolicyBundle& bundle);

Result<Digest> compute_bundle_integrity_digest(const PolicyBundle& bundle);
Result<Digest> compute_bundle_compatibility_digest(const PolicyBundle& bundle);
// Digest of the authored content only: everything a publisher states, without the generation the
// federation assigns and without the derived integrity and compatibility digests. Two publications
// with the same identity and the same content digest are the same publication.
Result<Digest> compute_bundle_content_digest(const PolicyBundle& bundle);

bool bundle_is_expired_at(const PolicyBundle& bundle, Timestamp now) noexcept;
bool bundle_is_effective_at(const PolicyBundle& bundle, Timestamp now) noexcept;
bool bundle_applies_to_site(const PolicyBundle& bundle, MemberId member, SiteId site) noexcept;

// ---------------------------------------------------------------------------------------
// Local override
// ---------------------------------------------------------------------------------------

// An override is generation-bound: it names the exact bundle generation and rule digest it
// replaces. When the underlying rule changes, the override is superseded instead of silently
// applying to a rule its author never saw.
struct LocalOverride {
  OverrideId id;
  FederationId federation;
  SiteId site;
  MemberId member;
  std::string domain;
  std::string subject;

  RuleId target_rule;
  Digest target_rule_digest{};
  PolicyBundleId target_bundle;
  Generation target_bundle_generation{};
  Digest target_bundle_digest{};

  Generation local_generation{};  // local generation created by registering this override
  SettingValue value{};
  GrantId authority{};  // delegated override authority; may be nil for permission Allowed
  std::string author;
  std::string reason;
  Timestamp created_at{};
  Timestamp expires_at{};  // zero means "no declared expiry"
  Digest digest{};         // computed and verified

  std::string key() const;
  bool is_expired_at(Timestamp now) const noexcept;
};

constexpr std::size_t kMaxOverrideReasonLength = 512;

Status validate_override(const LocalOverride& override_record);
Status seal_override(LocalOverride& override_record);
Result<Digest> compute_override_digest(const LocalOverride& override_record);

// ---------------------------------------------------------------------------------------
// Capability negotiation
// ---------------------------------------------------------------------------------------

struct CapabilityRef {
  std::string capability;
  SemanticVersion version{};

  friend bool operator==(const CapabilityRef&, const CapabilityRef&) noexcept = default;
};

// The federation's knowledge of which capabilities exist at all. A requirement naming a
// capability outside this catalog is unknown, not unsupported.
struct CapabilityCatalog {
  Generation generation{};
  std::vector<CapabilityRef> capabilities;

  const CapabilityRef* find(std::string_view capability) const noexcept;
};

// A site's declaration plus the catalog generation it was formed against. A stale snapshot can
// claim neither support nor absence.
struct CapabilitySnapshot {
  Generation catalog_generation{};
  std::vector<CapabilityRef> capabilities;

  const CapabilityRef* find(std::string_view capability) const noexcept;
};
using SiteCapabilitySnapshot = CapabilitySnapshot;

enum class NegotiationOutcome : std::uint8_t {
  Satisfied = 0,
  UnsupportedCapability = 1,  // site reports it does not implement this capability
  UnknownCapability = 2,      // neither catalog nor site can speak to it: defer
  VersionMismatch = 3,        // implemented, but older than required: incompatible
  CatalogStale = 4,           // catalog moved on since the site declaration: defer
};

const char* negotiation_outcome_name(NegotiationOutcome value) noexcept;

struct NegotiationResult {
  NegotiationOutcome outcome{NegotiationOutcome::Satisfied};
  CapabilityRequirement requirement{};
  std::string detail;
};

// Deterministic refinement. The catalog is authoritative about existence, the snapshot about
// implementation. Never collapses unknown into unsupported.
NegotiationOutcome negotiate_capability(const CapabilityRequirement& requirement,
                                        const SiteCapabilitySnapshot& snapshot,
                                        const CapabilityCatalog& catalog) noexcept;

Status validate_capability_catalog(const CapabilityCatalog& catalog);
Status validate_capability_snapshot(const SiteCapabilitySnapshot& snapshot);

// ---------------------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------------------

JsonValue rule_to_json(const Rule& rule);
Result<Rule> rule_from_json(const JsonValue& value);

JsonValue scope_to_json(const RuleScope& scope);
Result<RuleScope> scope_from_json(const JsonValue& value);

JsonValue setting_value_to_json(const SettingValue& value);
Result<SettingValue> setting_value_from_json(const JsonValue& value);

JsonValue bundle_to_json(const PolicyBundle& bundle);
Result<PolicyBundle> bundle_from_json(const JsonValue& value);

JsonValue override_to_json(const LocalOverride& override_record);
Result<LocalOverride> override_from_json(const JsonValue& value);

JsonValue capability_catalog_to_json(const CapabilityCatalog& catalog);
Result<CapabilityCatalog> capability_catalog_from_json(const JsonValue& value);

JsonValue capability_snapshot_to_json(const CapabilitySnapshot& snapshot);
Result<CapabilitySnapshot> capability_snapshot_from_json(const JsonValue& value);

}  // namespace gpf
