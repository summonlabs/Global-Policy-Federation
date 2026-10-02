#include "gpf/policy.hpp"

#include <algorithm>
#include <cstdio>
#include <set>

namespace gpf {
namespace {

constexpr Millis kMaxStalenessMs = 365ll * 24ll * 60ll * 60ll * 1000ll;
constexpr std::uint32_t kMaxPrecedence = 1000000u;

Status invalid(std::string message, std::string detail = {}) {
  return Status::failure(ErrorCode::InvalidArgument, std::move(message), std::move(detail));
}

bool contains_id(const std::vector<MemberId>& ids, MemberId id) {
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

bool contains_id(const std::vector<SiteId>& ids, SiteId id) {
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

// Conservative overlap: true when two scopes can select the same site. Member and site scoped
// rules are treated as potentially overlapping because bundle validation has no membership map;
// the effective-policy compiler refines this with the real member map.
bool scopes_overlap(const RuleScope& a, const RuleScope& b) {
  if (a.is_federation_wide() || b.is_federation_wide()) return true;
  if (a.level == ScopeLevel::Member && b.level == ScopeLevel::Member) {
    for (MemberId id : a.members) {
      if (contains_id(b.members, id)) return true;
    }
    return false;
  }
  if (a.level == ScopeLevel::Site && b.level == ScopeLevel::Site) {
    for (SiteId id : a.sites) {
      if (contains_id(b.sites, id)) return true;
    }
    return false;
  }
  return true;
}

bool scope_contains(const RuleScope& outer, const RuleScope& inner, const MembershipBinding* binding) {
  if (outer.is_federation_wide()) return true;
  if (outer.level == ScopeLevel::Member) {
    if (inner.level == ScopeLevel::Federation) return false;
    if (inner.level == ScopeLevel::Site) {
      // A member-scoped grant covers a site only when the membership binding says the site
      // belongs to that member. Without the binding this cannot be established.
      if (binding == nullptr || inner.sites.empty()) return false;
      for (SiteId id : inner.sites) {
        if (!binding->binds_site_to_any(outer.members, id)) return false;
      }
      return true;
    }
    for (MemberId id : inner.members) {
      if (!contains_id(outer.members, id)) return false;
    }
    return !inner.members.empty();
  }
  // outer is site scoped: only site scopes that are a subset are contained
  if (inner.level != ScopeLevel::Site) return false;
  for (SiteId id : inner.sites) {
    if (!contains_id(outer.sites, id)) return false;
  }
  return !inner.sites.empty();
}

void write_version(CanonicalWriter& writer, const SemanticVersion& version) {
  writer.u32(version.major).u32(version.minor).u32(version.patch);
}

void write_scope(CanonicalWriter& writer, const RuleScope& scope) {
  writer.u8(static_cast<std::uint8_t>(scope.level));
  writer.u64(static_cast<std::uint64_t>(scope.members.size()));
  for (MemberId id : scope.members) writer.id(id.value);
  writer.u64(static_cast<std::uint64_t>(scope.sites.size()));
  for (SiteId id : scope.sites) writer.id(id.value);
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

std::vector<CapabilityRequirement> sorted_requirements(const std::vector<CapabilityRequirement>& in) {
  std::vector<CapabilityRequirement> out = in;
  std::sort(out.begin(), out.end(), [](const CapabilityRequirement& a, const CapabilityRequirement& b) {
    return a.capability < b.capability;
  });
  return out;
}

template <class IdType>
Result<IdType> id_from_json(const JsonValue& value, const char* key) {
  auto text = value.require_string(key);
  if (!text) return Result<IdType>::failure(text.error);
  return IdType::parse(*text);
}

Result<SemanticVersion> version_from_json(const JsonValue& value, const char* key) {
  auto text = value.require_string(key);
  if (!text) return Result<SemanticVersion>::failure(text.error);
  return SemanticVersion::parse(*text);
}

Result<Timestamp> timestamp_from_json(const JsonValue& value, const char* key) {
  auto raw = value.require_int_in_range(key, INT64_MIN, INT64_MAX);
  if (!raw) return Result<Timestamp>::failure(raw.error);
  return Result<Timestamp>::success(Timestamp{*raw});
}

Result<Digest> digest_from_json(const JsonValue& value, const char* key) {
  auto text = value.require_string(key);
  if (!text) return Result<Digest>::failure(text.error);
  return Digest::from_hex(*text);
}

Result<Generation> generation_from_json(const JsonValue& value, const char* key) {
  auto raw = value.require_int_in_range(key, 0, INT64_MAX);
  if (!raw) return Result<Generation>::failure(raw.error);
  if (static_cast<std::uint64_t>(*raw) > limits::kMaxGenerationValue) {
    return Result<Generation>::failure(ErrorCode::Overflow,
                                       "generation exceeds the supported range", key);
  }
  return Result<Generation>::success(Generation{static_cast<std::uint64_t>(*raw)});
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Semantic versions
// ---------------------------------------------------------------------------------------

std::string SemanticVersion::to_string() const {
  return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
}

Result<SemanticVersion> SemanticVersion::parse(std::string_view text) {
  std::vector<std::string> parts = split_ascii(text, '.');
  if (parts.size() != 3) {
    return Result<SemanticVersion>::failure(ErrorCode::MalformedInput,
                                            "version must have three dot-separated components",
                                            escape_preview(text));
  }
  SemanticVersion out;
  std::uint32_t* targets[3] = {&out.major, &out.minor, &out.patch};
  for (std::size_t i = 0; i < 3; ++i) {
    const std::string& part = parts[i];
    if (part.empty() || part.size() > 9) {
      return Result<SemanticVersion>::failure(ErrorCode::MalformedInput, "version component is invalid",
                                              escape_preview(text));
    }
    std::uint32_t value = 0;
    for (char c : part) {
      if (c < '0' || c > '9') {
        return Result<SemanticVersion>::failure(ErrorCode::MalformedInput,
                                                "version component is not numeric", escape_preview(text));
      }
      value = value * 10u + static_cast<std::uint32_t>(c - '0');
    }
    *targets[i] = value;
  }
  return Result<SemanticVersion>::success(out);
}

bool SemanticVersion::backward_compatible_with(const SemanticVersion& consumer) const noexcept {
  return major == consumer.major && minor <= consumer.minor;
}

// ---------------------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------------------

const char* rule_class_name(RuleClass value) noexcept {
  switch (value) {
    case RuleClass::Advisory: return "advisory";
    case RuleClass::Default: return "default";
    case RuleClass::Mandatory: return "mandatory";
  }
  return "unknown";
}

Result<RuleClass> rule_class_from_name(std::string_view name) {
  if (name == "advisory") return Result<RuleClass>::success(RuleClass::Advisory);
  if (name == "default") return Result<RuleClass>::success(RuleClass::Default);
  if (name == "mandatory") return Result<RuleClass>::success(RuleClass::Mandatory);
  return Result<RuleClass>::failure(ErrorCode::MalformedInput, "unknown rule class",
                                    escape_preview(name));
}

const char* scope_level_name(ScopeLevel value) noexcept {
  switch (value) {
    case ScopeLevel::Federation: return "federation";
    case ScopeLevel::Member: return "member";
    case ScopeLevel::Site: return "site";
  }
  return "unknown";
}

Result<ScopeLevel> scope_level_from_name(std::string_view name) {
  if (name == "federation") return Result<ScopeLevel>::success(ScopeLevel::Federation);
  if (name == "member") return Result<ScopeLevel>::success(ScopeLevel::Member);
  if (name == "site") return Result<ScopeLevel>::success(ScopeLevel::Site);
  return Result<ScopeLevel>::failure(ErrorCode::MalformedInput, "unknown scope level",
                                     escape_preview(name));
}

const char* override_permission_name(OverridePermission value) noexcept {
  switch (value) {
    case OverridePermission::Prohibited: return "prohibited";
    case OverridePermission::AllowedWithAuthority: return "allowed-with-authority";
    case OverridePermission::Allowed: return "allowed";
  }
  return "unknown";
}

Result<OverridePermission> override_permission_from_name(std::string_view name) {
  if (name == "prohibited") return Result<OverridePermission>::success(OverridePermission::Prohibited);
  if (name == "allowed-with-authority") {
    return Result<OverridePermission>::success(OverridePermission::AllowedWithAuthority);
  }
  if (name == "allowed") return Result<OverridePermission>::success(OverridePermission::Allowed);
  return Result<OverridePermission>::failure(ErrorCode::MalformedInput, "unknown override permission",
                                             escape_preview(name));
}

const char* staleness_mode_name(StalenessPolicy::Mode value) noexcept {
  switch (value) {
    case StalenessPolicy::Mode::RequireFresh: return "require-fresh";
    case StalenessPolicy::Mode::AllowLastKnownValid: return "allow-last-known-valid";
  }
  return "unknown";
}

Result<StalenessPolicy::Mode> staleness_mode_from_name(std::string_view name) {
  if (name == "require-fresh") return Result<StalenessPolicy::Mode>::success(StalenessPolicy::Mode::RequireFresh);
  if (name == "allow-last-known-valid") {
    return Result<StalenessPolicy::Mode>::success(StalenessPolicy::Mode::AllowLastKnownValid);
  }
  return Result<StalenessPolicy::Mode>::failure(ErrorCode::MalformedInput, "unknown staleness mode",
                                               escape_preview(name));
}

const char* negotiation_outcome_name(NegotiationOutcome value) noexcept {
  switch (value) {
    case NegotiationOutcome::Satisfied: return "satisfied";
    case NegotiationOutcome::UnsupportedCapability: return "unsupported";
    case NegotiationOutcome::UnknownCapability: return "unknown";
    case NegotiationOutcome::VersionMismatch: return "version-mismatch";
    case NegotiationOutcome::CatalogStale: return "catalog-stale";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------------------
// Scope and values
// ---------------------------------------------------------------------------------------

RuleScope RuleScope::federation() { return RuleScope{}; }

RuleScope RuleScope::for_members(std::vector<MemberId> members) {
  RuleScope scope;
  scope.level = ScopeLevel::Member;
  scope.members = std::move(members);
  return scope;
}

RuleScope RuleScope::for_sites(std::vector<SiteId> sites) {
  RuleScope scope;
  scope.level = ScopeLevel::Site;
  scope.sites = std::move(sites);
  return scope;
}

bool scope_contains_site(const RuleScope& scope, MemberId member, SiteId site) noexcept {
  switch (scope.level) {
    case ScopeLevel::Federation:
      return true;
    case ScopeLevel::Member:
      return contains_id(scope.members, member);
    case ScopeLevel::Site:
      return contains_id(scope.sites, site);
  }
  return false;
}

bool MembershipBinding::contains(MemberId member, SiteId site) const noexcept {
  for (const auto& entry : entries) {
    if (entry.first == member && entry.second == site) return true;
  }
  return false;
}

bool MembershipBinding::binds_site_to_any(const std::vector<MemberId>& members, SiteId site) const noexcept {
  for (const auto& entry : entries) {
    if (!(entry.second == site)) continue;
    for (MemberId member : members) {
      if (member == entry.first) return true;
    }
  }
  return false;
}

Status validate_membership_binding(const MembershipBinding& binding) {
  if (binding.entries.size() > limits::kMaxSitesPerFederation) {
    return Status::failure(ErrorCode::TooLarge, "membership binding exceeds the site limit", {});
  }
  std::set<std::string> seen_sites;
  for (const auto& entry : binding.entries) {
    if (entry.first.is_nil()) return invalid("membership binding has a nil member");
    if (entry.second.is_nil()) return invalid("membership binding has a nil site");
    // A site belongs to exactly one member. A conflicting binding is a defect in the neighboring
    // truth, not something to resolve here.
    if (!seen_sites.insert(entry.second.to_string()).second) {
      return Status::failure(ErrorCode::Conflict, "membership binding assigns a site more than once",
                             entry.second.to_string());
    }
  }
  return Status::success();
}

bool scope_contains_scope(const RuleScope& outer, const RuleScope& inner, const MembershipBinding* binding) {
  return scope_contains(outer, inner, binding);
}

Status validate_scope(const RuleScope& scope) {
  constexpr std::size_t kMaxScopeTargets = 4096;
  if (!scope.members.empty() && !scope.sites.empty()) {
    return invalid("scope mixes member and site targets");
  }
  if (scope.level == ScopeLevel::Federation) {
    if (!scope.members.empty() || !scope.sites.empty()) {
      return invalid("federation scope must not carry member or site targets");
    }
    return Status::success();
  }
  if (scope.level == ScopeLevel::Member) {
    if (scope.members.empty()) return invalid("member scope requires at least one member target");
    if (scope.sites.size() > 0) return invalid("member scope must not carry site targets");
    if (scope.members.size() > kMaxScopeTargets) return Status::failure(ErrorCode::TooLarge, "scope has too many member targets", {});
  }
  if (scope.level == ScopeLevel::Site) {
    if (scope.sites.empty()) return invalid("site scope requires at least one site target");
    if (scope.members.size() > 0) return invalid("site scope must not carry member targets");
    if (scope.sites.size() > kMaxScopeTargets) return Status::failure(ErrorCode::TooLarge, "scope has too many site targets", {});
  }
  std::set<std::string> seen;
  for (MemberId id : scope.members) {
    if (id.is_nil()) return invalid("scope carries a nil member identity");
    if (!seen.insert(id.to_string()).second) return invalid("scope repeats a member identity", id.to_string());
  }
  for (SiteId id : scope.sites) {
    if (id.is_nil()) return invalid("scope carries a nil site identity");
    if (!seen.insert(id.to_string()).second) return invalid("scope repeats a site identity", id.to_string());
  }
  return Status::success();
}

SettingValue SettingValue::unset() { return SettingValue{}; }

SettingValue SettingValue::boolean_value(bool value) {
  SettingValue out;
  out.type = Type::Boolean;
  out.boolean = value;
  return out;
}

SettingValue SettingValue::integer_value(std::int64_t value) {
  SettingValue out;
  out.type = Type::Integer;
  out.integer = value;
  return out;
}

SettingValue SettingValue::text_value(std::string value) {
  SettingValue out;
  out.type = Type::Text;
  out.text = std::move(value);
  return out;
}

const char* SettingValue::type_name() const noexcept {
  switch (type) {
    case Type::Unset: return "unset";
    case Type::Boolean: return "boolean";
    case Type::Integer: return "integer";
    case Type::Text: return "text";
  }
  return "unknown";
}

std::string SettingValue::to_display_string() const {
  switch (type) {
    case Type::Unset: return "unset";
    case Type::Boolean: return boolean ? "true" : "false";
    case Type::Integer: return std::to_string(integer);
    case Type::Text: return text;
  }
  return "unknown";
}

bool operator==(const SettingValue& a, const SettingValue& b) noexcept {
  if (a.type != b.type) return false;
  switch (a.type) {
    case SettingValue::Type::Unset: return true;
    case SettingValue::Type::Boolean: return a.boolean == b.boolean;
    case SettingValue::Type::Integer: return a.integer == b.integer;
    case SettingValue::Type::Text: return a.text == b.text;
  }
  return false;
}

StalenessPolicy StalenessPolicy::require_fresh() { return StalenessPolicy{}; }

StalenessPolicy StalenessPolicy::allow_last_known_valid(Millis max_staleness_ms) {
  StalenessPolicy out;
  out.mode = Mode::AllowLastKnownValid;
  out.max_staleness_ms = max_staleness_ms;
  return out;
}

Status validate_capability_requirement(const CapabilityRequirement& requirement) {
  if (!is_valid_identifier(requirement.capability)) {
    return invalid("capability requirement names an invalid capability",
                   escape_preview(requirement.capability));
  }
  if (requirement.min_version.major == 0) {
    return invalid("capability requirement needs a major version of at least 1",
                   requirement.capability);
  }
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------------------

std::string Rule::key() const { return domain + "/" + subject; }

bool Rule::is_expired_at(Timestamp now) const noexcept {
  return expires_at.ms != 0 && now.ms >= expires_at.ms;
}

bool Rule::is_effective_at(Timestamp now) const noexcept {
  if (effective_from.ms != 0 && now.ms < effective_from.ms) return false;
  return !is_expired_at(now);
}

bool Rule::applies_to(MemberId member, SiteId site) const noexcept {
  return scope_contains_site(scope, member, site);
}

Status validate_rule(const Rule& rule) {
  if (rule.id.is_nil()) return invalid("rule identity is nil");
  if (!is_valid_identifier(rule.domain)) {
    return invalid("rule conflict domain is not a valid identifier", escape_preview(rule.domain));
  }
  if (!is_valid_identifier(rule.subject)) {
    return invalid("rule subject is not a valid identifier", escape_preview(rule.subject));
  }
  if (rule.version.major == 0) return invalid("rule version major must be at least 1", rule.key());
  auto scope_status = validate_scope(rule.scope);
  if (!scope_status.ok()) return scope_status;
  if (!rule.value.is_set()) return invalid("rule carries no value", rule.key());
  if (rule.value.type == SettingValue::Type::Text) {
    if (!is_valid_utf8(rule.value.text)) return invalid("rule text value is not valid UTF-8", rule.key());
    if (rule.value.text.size() > limits::kMaxTextLength) {
      return Status::failure(ErrorCode::TooLarge, "rule text value exceeds the length limit", rule.key());
    }
  }
  if (rule.capability_requirements.size() > limits::kMaxCapabilityRequirementsPerRule) {
    return Status::failure(ErrorCode::TooLarge, "rule declares too many capability requirements", rule.key());
  }
  std::set<std::string> capabilities;
  for (const auto& requirement : rule.capability_requirements) {
    auto status = validate_capability_requirement(requirement);
    if (!status.ok()) return status;
    if (!capabilities.insert(requirement.capability).second) {
      return invalid("rule repeats a capability requirement", requirement.capability);
    }
  }
  if (rule.precedence > kMaxPrecedence) {
    return invalid("rule precedence exceeds the supported range", rule.key());
  }
  // Precedence is a mandatory-policy concept only. Allowing it elsewhere would create a second,
  // undocumented authority ordering for defaults and advisories.
  if (rule.rule_class != RuleClass::Mandatory && rule.precedence != 0) {
    return invalid("only mandatory rules may declare precedence", rule.key());
  }
  // Override permission is meaningful only where policy binds.
  if (rule.rule_class != RuleClass::Mandatory && rule.override_permission != OverridePermission::Allowed) {
    return invalid("non-mandatory rules may only use override permission 'allowed'", rule.key());
  }
  if (rule.staleness.mode == StalenessPolicy::Mode::AllowLastKnownValid) {
    if (rule.staleness.max_staleness_ms <= 0 || rule.staleness.max_staleness_ms > kMaxStalenessMs) {
      return invalid("last-known-valid window is outside the supported range", rule.key());
    }
    // Last-known-valid is a concession granted by binding policy, never a default behavior.
    if (rule.rule_class != RuleClass::Mandatory) {
      return invalid("last-known-valid staleness is only meaningful for mandatory rules", rule.key());
    }
  }
  if (rule.expires_at.ms != 0 && rule.expires_at.ms <= rule.effective_from.ms) {
    return invalid("rule expires at or before it becomes effective", rule.key());
  }
  if (!is_valid_utf8(rule.rationale)) return invalid("rule rationale is not valid UTF-8", rule.key());
  if (rule.rationale.size() > limits::kMaxRationaleLength) {
    return Status::failure(ErrorCode::TooLarge, "rule rationale exceeds the length limit", rule.key());
  }
  return Status::success();
}

Result<Digest> compute_rule_digest(const Rule& rule) {
  CanonicalWriter writer;
  writer.tag("gpf.rule.v1");
  writer.id(rule.id.value);
  writer.str(rule.version.to_string());
  writer.str(rule.domain);
  writer.str(rule.subject);
  writer.u8(static_cast<std::uint8_t>(rule.rule_class));
  writer.u32(rule.precedence);
  write_scope(writer, rule.scope);
  write_value(writer, rule.value);
  const auto requirements = sorted_requirements(rule.capability_requirements);
  writer.u64(static_cast<std::uint64_t>(requirements.size()));
  for (const auto& requirement : requirements) {
    writer.str(requirement.capability);
    write_version(writer, requirement.min_version);
    writer.boolean(requirement.optional);
  }
  writer.u8(static_cast<std::uint8_t>(rule.override_permission));
  writer.u8(static_cast<std::uint8_t>(rule.staleness.mode));
  writer.i64(rule.staleness.max_staleness_ms);
  writer.i64(rule.effective_from.ms);
  writer.i64(rule.expires_at.ms);
  writer.str(rule.rationale);
  return Result<Digest>::success(writer.digest());
}

// ---------------------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------------------

Result<Digest> compute_provenance_digest(const ProvenanceEntry& entry) {
  CanonicalWriter writer;
  writer.tag("gpf.provenance.v1");
  writer.str(entry.actor);
  writer.id(entry.member.value);
  writer.id(entry.grant.value);
  writer.u64(entry.authority_epoch.value);
  writer.u64(entry.generation.value);
  writer.i64(entry.at.ms);
  writer.digest(entry.previous);
  writer.str(entry.note);
  return Result<Digest>::success(writer.digest());
}

Status validate_provenance_chain(const std::vector<ProvenanceEntry>& chain) {
  if (chain.empty()) {
    return invalid("bundle has no provenance entry: the publisher of policy must be attributable");
  }
  if (chain.size() > limits::kMaxProvenanceEntries) {
    return Status::failure(ErrorCode::TooLarge, "provenance chain exceeds the length limit", {});
  }
  Digest expected_previous{};
  for (std::size_t i = 0; i < chain.size(); ++i) {
    const ProvenanceEntry& entry = chain[i];
    if (entry.actor.empty() || entry.actor.size() > limits::kMaxShortTextLength ||
        !is_valid_utf8(entry.actor)) {
      return invalid("provenance entry has an invalid actor", std::to_string(i));
    }
    if (entry.member.is_nil()) return invalid("provenance entry has a nil member", std::to_string(i));
    if (entry.generation.is_nil()) return invalid("provenance entry has a nil generation", std::to_string(i));
    if (!is_valid_utf8(entry.note)) return invalid("provenance note is not valid UTF-8", std::to_string(i));
    if (entry.previous != expected_previous) {
      return Status::failure(ErrorCode::IntegrityFailure, "provenance chain is broken",
                             "entry " + std::to_string(i));
    }
    auto computed = compute_provenance_digest(entry);
    if (!computed) return Status::failure(computed.error);
    if (entry.entry_digest != *computed) {
      return Status::failure(ErrorCode::IntegrityFailure, "provenance entry digest does not match",
                             "entry " + std::to_string(i));
    }
    expected_previous = *computed;
  }
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Policy bundle
// ---------------------------------------------------------------------------------------

void normalize_bundle(PolicyBundle& bundle) {
  std::sort(bundle.rules.begin(), bundle.rules.end(),
            [](const Rule& a, const Rule& b) { return a.id < b.id; });
  for (Rule& rule : bundle.rules) {
    std::sort(rule.scope.members.begin(), rule.scope.members.end());
    rule.scope.members.erase(std::unique(rule.scope.members.begin(), rule.scope.members.end()),
                             rule.scope.members.end());
    std::sort(rule.scope.sites.begin(), rule.scope.sites.end());
    rule.scope.sites.erase(std::unique(rule.scope.sites.begin(), rule.scope.sites.end()),
                           rule.scope.sites.end());
    rule.capability_requirements = sorted_requirements(rule.capability_requirements);
  }
  std::sort(bundle.scope.members.begin(), bundle.scope.members.end());
  bundle.scope.members.erase(std::unique(bundle.scope.members.begin(), bundle.scope.members.end()),
                             bundle.scope.members.end());
  std::sort(bundle.scope.sites.begin(), bundle.scope.sites.end());
  bundle.scope.sites.erase(std::unique(bundle.scope.sites.begin(), bundle.scope.sites.end()),
                           bundle.scope.sites.end());
}

Status validate_bundle(const PolicyBundle& bundle) {
  if (bundle.id.is_nil()) return invalid("bundle identity is nil");
  if (bundle.federation.is_nil()) return invalid("bundle federation is nil");
  if (bundle.issuer_member.is_nil()) return invalid("bundle issuer member is nil");
  if (bundle.global_generation.is_nil()) {
    return invalid("bundle global generation is nil: authority must be generation-bound");
  }
  if (bundle.global_generation.value > limits::kMaxGenerationValue) {
    return Status::failure(ErrorCode::Overflow, "bundle generation exceeds the supported range", {});
  }
  auto scope_status = validate_scope(bundle.scope);
  if (!scope_status.ok()) return scope_status;
  if (bundle.required_runtime.major == 0) {
    return invalid("bundle must declare a required runtime major version");
  }
  if (bundle.rules.size() > limits::kMaxRulesPerBundle) {
    return Status::failure(ErrorCode::TooLarge, "bundle carries too many rules",
                           std::to_string(bundle.rules.size()));
  }
  if (bundle.expires_at.ms != 0 && bundle.expires_at.ms <= bundle.effective_from.ms) {
    return invalid("bundle expires at or before it becomes effective");
  }
  if (bundle.staleness.mode == StalenessPolicy::Mode::AllowLastKnownValid) {
    if (bundle.staleness.max_staleness_ms <= 0 || bundle.staleness.max_staleness_ms > kMaxStalenessMs) {
      return invalid("bundle last-known-valid window is outside the supported range");
    }
  }
  std::set<std::string> rule_ids;
  for (const Rule& rule : bundle.rules) {
    auto status = validate_rule(rule);
    if (!status.ok()) return status;
    if (!rule_ids.insert(rule.id.to_string()).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "bundle repeats a rule identity",
                             rule.id.to_string());
    }
    // A bundle may never widen its own scope: rules must live inside the publication scope.
    if (!scope_contains(bundle.scope, rule.scope, nullptr)) {
      return invalid("bundle carries a rule whose scope exceeds the bundle scope", rule.key());
    }
  }
  // Contradictions inside one bundle are authoring defects, not runtime conflicts.
  for (std::size_t i = 0; i < bundle.rules.size(); ++i) {
    for (std::size_t j = i + 1; j < bundle.rules.size(); ++j) {
      const Rule& a = bundle.rules[i];
      const Rule& b = bundle.rules[j];
      if (a.key() != b.key() || a.rule_class != b.rule_class) continue;
      if (!scopes_overlap(a.scope, b.scope)) continue;
      if (a.rule_class == RuleClass::Mandatory && a.precedence != b.precedence) continue;
      if (a.value == b.value) continue;
      return Status::failure(ErrorCode::Conflict,
                             "bundle contains contradictory rules for one subject and class",
                             a.id.to_string() + " vs " + b.id.to_string());
    }
  }
  return validate_provenance_chain(bundle.provenance);
}

Result<Digest> compute_bundle_integrity_digest(const PolicyBundle& bundle) {
  std::vector<std::pair<RuleId, Digest>> rule_digests;
  rule_digests.reserve(bundle.rules.size());
  for (const Rule& rule : bundle.rules) {
    auto digest = compute_rule_digest(rule);
    if (!digest) return Result<Digest>::failure(digest.error);
    rule_digests.emplace_back(rule.id, *digest);
  }
  std::sort(rule_digests.begin(), rule_digests.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

  CanonicalWriter writer;
  writer.tag("gpf.bundle.integrity.v1");
  writer.id(bundle.id.value);
  writer.id(bundle.federation.value);
  writer.u64(bundle.global_generation.value);
  writer.id(bundle.issuer_member.value);
  write_scope(writer, bundle.scope);
  writer.i64(bundle.issued_at.ms);
  writer.i64(bundle.effective_from.ms);
  writer.i64(bundle.expires_at.ms);
  writer.str(bundle.required_runtime.to_string());
  writer.u64(bundle.capability_catalog_generation.value);
  writer.u8(static_cast<std::uint8_t>(bundle.staleness.mode));
  writer.i64(bundle.staleness.max_staleness_ms);
  writer.u64(static_cast<std::uint64_t>(rule_digests.size()));
  for (const auto& entry : rule_digests) {
    writer.id(entry.first.value);
    writer.digest(entry.second);
  }
  writer.u64(static_cast<std::uint64_t>(bundle.provenance.size()));
  for (const ProvenanceEntry& entry : bundle.provenance) {
    writer.digest(entry.entry_digest);
  }
  return Result<Digest>::success(writer.digest());
}

Result<Digest> compute_bundle_compatibility_digest(const PolicyBundle& bundle) {
  CanonicalWriter writer;
  writer.tag("gpf.bundle.compatibility.v1");
  writer.str(bundle.required_runtime.to_string());
  writer.u64(bundle.capability_catalog_generation.value);

  std::vector<CapabilityRequirement> requirements;
  std::vector<std::string> surface;
  for (const Rule& rule : bundle.rules) {
    for (const auto& requirement : rule.capability_requirements) {
      requirements.push_back(requirement);
    }
    surface.push_back(rule.domain + "/" + rule.subject + "@" + std::to_string(rule.version.major));
  }
  std::sort(requirements.begin(), requirements.end(),
            [](const CapabilityRequirement& a, const CapabilityRequirement& b) {
              return a.capability < b.capability;
            });
  requirements.erase(std::unique(requirements.begin(), requirements.end(),
                                 [](const CapabilityRequirement& a, const CapabilityRequirement& b) {
                                   return a.capability == b.capability &&
                                          a.min_version == b.min_version && a.optional == b.optional;
                                 }),
                     requirements.end());
  writer.u64(static_cast<std::uint64_t>(requirements.size()));
  for (const auto& requirement : requirements) {
    writer.str(requirement.capability);
    write_version(writer, requirement.min_version);
    writer.boolean(requirement.optional);
  }
  std::sort(surface.begin(), surface.end());
  surface.erase(std::unique(surface.begin(), surface.end()), surface.end());
  writer.u64(static_cast<std::uint64_t>(surface.size()));
  for (const std::string& entry : surface) writer.str(entry);
  return Result<Digest>::success(writer.digest());
}

Result<Digest> compute_bundle_content_digest(const PolicyBundle& bundle) {
  std::vector<std::pair<RuleId, Digest>> rule_digests;
  rule_digests.reserve(bundle.rules.size());
  for (const Rule& rule : bundle.rules) {
    auto digest = compute_rule_digest(rule);
    if (!digest) return Result<Digest>::failure(digest.error);
    rule_digests.emplace_back(rule.id, *digest);
  }
  std::sort(rule_digests.begin(), rule_digests.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

  CanonicalWriter writer;
  writer.tag("gpf.bundle.content.v1");
  writer.id(bundle.id.value);
  writer.id(bundle.federation.value);
  writer.id(bundle.issuer_member.value);
  write_scope(writer, bundle.scope);
  writer.i64(bundle.issued_at.ms);
  writer.i64(bundle.effective_from.ms);
  writer.i64(bundle.expires_at.ms);
  writer.str(bundle.required_runtime.to_string());
  writer.u64(bundle.capability_catalog_generation.value);
  writer.u8(static_cast<std::uint8_t>(bundle.staleness.mode));
  writer.i64(bundle.staleness.max_staleness_ms);
  writer.u64(static_cast<std::uint64_t>(rule_digests.size()));
  for (const auto& entry : rule_digests) {
    writer.id(entry.first.value);
    writer.digest(entry.second);
  }
  writer.u64(static_cast<std::uint64_t>(bundle.provenance.size()));
  for (const ProvenanceEntry& entry : bundle.provenance) {
    writer.str(entry.actor);
    writer.id(entry.member.value);
    writer.id(entry.grant.value);
    writer.u64(entry.authority_epoch.value);
    writer.u64(entry.generation.value);
    writer.i64(entry.at.ms);
    writer.digest(entry.previous);
    writer.str(entry.note);
  }
  return Result<Digest>::success(writer.digest());
}

Status seal_bundle(PolicyBundle& bundle) {
  normalize_bundle(bundle);
  auto integrity = compute_bundle_integrity_digest(bundle);
  if (!integrity) return Status::failure(integrity.error);
  auto compatibility = compute_bundle_compatibility_digest(bundle);
  if (!compatibility) return Status::failure(compatibility.error);
  bundle.integrity_digest = *integrity;
  bundle.compatibility_digest = *compatibility;
  return Status::success();
}

Status verify_bundle(const PolicyBundle& bundle) {
  auto status = validate_bundle(bundle);
  if (!status.ok()) return status;
  auto integrity = compute_bundle_integrity_digest(bundle);
  if (!integrity) return Status::failure(integrity.error);
  if (*integrity != bundle.integrity_digest) {
    return Status::failure(ErrorCode::IntegrityFailure, "bundle integrity digest does not match content",
                           bundle.id.to_string());
  }
  auto compatibility = compute_bundle_compatibility_digest(bundle);
  if (!compatibility) return Status::failure(compatibility.error);
  if (*compatibility != bundle.compatibility_digest) {
    return Status::failure(ErrorCode::IntegrityFailure,
                           "bundle compatibility digest does not match content", bundle.id.to_string());
  }
  return Status::success();
}

bool bundle_is_expired_at(const PolicyBundle& bundle, Timestamp now) noexcept {
  return bundle.expires_at.ms != 0 && now.ms >= bundle.expires_at.ms;
}

bool bundle_is_effective_at(const PolicyBundle& bundle, Timestamp now) noexcept {
  if (bundle.effective_from.ms != 0 && now.ms < bundle.effective_from.ms) return false;
  return !bundle_is_expired_at(bundle, now);
}

bool bundle_applies_to_site(const PolicyBundle& bundle, MemberId member, SiteId site) noexcept {
  return scope_contains_site(bundle.scope, member, site);
}

// ---------------------------------------------------------------------------------------
// Local override
// ---------------------------------------------------------------------------------------

std::string LocalOverride::key() const { return domain + "/" + subject; }

bool LocalOverride::is_expired_at(Timestamp now) const noexcept {
  return expires_at.ms != 0 && now.ms >= expires_at.ms;
}

Status validate_override(const LocalOverride& override_record) {
  if (override_record.id.is_nil()) return invalid("override identity is nil");
  if (override_record.federation.is_nil()) return invalid("override federation is nil");
  if (override_record.site.is_nil()) return invalid("override site is nil");
  if (override_record.member.is_nil()) return invalid("override member is nil");
  if (!is_valid_identifier(override_record.domain)) {
    return invalid("override conflict domain is not a valid identifier");
  }
  if (!is_valid_identifier(override_record.subject)) {
    return invalid("override subject is not a valid identifier");
  }
  if (override_record.target_rule.is_nil()) return invalid("override names no target rule");
  if (override_record.target_bundle.is_nil()) return invalid("override names no target bundle");
  if (override_record.target_bundle_generation.is_nil()) {
    return invalid("override must be bound to the generation it overrides");
  }
  if (override_record.target_rule_digest.is_zero() || override_record.target_bundle_digest.is_zero()) {
    return invalid("override must carry the digests of the rule and bundle it overrides");
  }
  if (override_record.local_generation.is_nil()) {
    return invalid("override must carry the local generation it created");
  }
  if (!override_record.value.is_set()) return invalid("override carries no value");
  if (override_record.value.type == SettingValue::Type::Text) {
    if (!is_valid_utf8(override_record.value.text)) return invalid("override value is not valid UTF-8");
    if (override_record.value.text.size() > limits::kMaxTextLength) {
      return Status::failure(ErrorCode::TooLarge, "override value exceeds the length limit", {});
    }
  }
  if (override_record.author.empty() || override_record.author.size() > limits::kMaxShortTextLength ||
      !is_valid_utf8(override_record.author)) {
    return invalid("override must be attributable to an author");
  }
  if (override_record.reason.empty() || override_record.reason.size() > kMaxOverrideReasonLength ||
      !is_valid_utf8(override_record.reason)) {
    return invalid("override must state a reason");
  }
  return Status::success();
}

Result<Digest> compute_override_digest(const LocalOverride& override_record) {
  CanonicalWriter writer;
  writer.tag("gpf.override.v1");
  writer.id(override_record.id.value);
  writer.id(override_record.federation.value);
  writer.id(override_record.site.value);
  writer.id(override_record.member.value);
  writer.str(override_record.domain);
  writer.str(override_record.subject);
  writer.id(override_record.target_rule.value);
  writer.digest(override_record.target_rule_digest);
  writer.id(override_record.target_bundle.value);
  writer.u64(override_record.target_bundle_generation.value);
  writer.digest(override_record.target_bundle_digest);
  writer.u64(override_record.local_generation.value);
  write_value(writer, override_record.value);
  writer.id(override_record.authority.value);
  writer.str(override_record.author);
  writer.str(override_record.reason);
  writer.i64(override_record.created_at.ms);
  writer.i64(override_record.expires_at.ms);
  return Result<Digest>::success(writer.digest());
}

Status seal_override(LocalOverride& override_record) {
  auto digest = compute_override_digest(override_record);
  if (!digest) return Status::failure(digest.error);
  override_record.digest = *digest;
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Capability negotiation
// ---------------------------------------------------------------------------------------

const CapabilityRef* CapabilityCatalog::find(std::string_view capability) const noexcept {
  for (const auto& entry : capabilities) {
    if (entry.capability == capability) return &entry;
  }
  return nullptr;
}

const CapabilityRef* CapabilitySnapshot::find(std::string_view capability) const noexcept {
  for (const auto& entry : capabilities) {
    if (entry.capability == capability) return &entry;
  }
  return nullptr;
}

Status validate_capability_catalog(const CapabilityCatalog& catalog) {
  if (catalog.capabilities.size() > limits::kMaxBundlesPerFederation) {
    return Status::failure(ErrorCode::TooLarge, "capability catalog exceeds the size limit", {});
  }
  std::set<std::string> seen;
  for (const auto& entry : catalog.capabilities) {
    if (!is_valid_identifier(entry.capability)) {
      return invalid("capability catalog entry names an invalid capability",
                     escape_preview(entry.capability));
    }
    if (entry.version.major == 0) {
      return invalid("capability catalog entry needs a major version of at least 1", entry.capability);
    }
    if (!seen.insert(entry.capability).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "capability catalog repeats a capability",
                             entry.capability);
    }
  }
  return Status::success();
}

Status validate_capability_snapshot(const SiteCapabilitySnapshot& snapshot) {
  if (snapshot.capabilities.size() > limits::kMaxBundlesPerFederation) {
    return Status::failure(ErrorCode::TooLarge, "capability snapshot exceeds the size limit", {});
  }
  std::set<std::string> seen;
  for (const auto& entry : snapshot.capabilities) {
    if (!is_valid_identifier(entry.capability)) {
      return invalid("capability snapshot entry names an invalid capability",
                     escape_preview(entry.capability));
    }
    if (entry.version.major == 0) {
      return invalid("capability snapshot entry needs a major version of at least 1", entry.capability);
    }
    if (!seen.insert(entry.capability).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "capability snapshot repeats a capability",
                             entry.capability);
    }
  }
  return Status::success();
}

NegotiationOutcome negotiate_capability(const CapabilityRequirement& requirement,
                                        const SiteCapabilitySnapshot& snapshot,
                                        const CapabilityCatalog& catalog) noexcept {
  // The catalog is authoritative about which capabilities exist. A requirement naming something
  // the federation has never published as a capability is unknown, never "unsupported".
  const CapabilityRef* known = catalog.find(requirement.capability);
  if (known == nullptr) return NegotiationOutcome::UnknownCapability;

  const CapabilityRef* declared = snapshot.find(requirement.capability);
  if (declared == nullptr) {
    // The site has not been told about this capability yet: absence of declaration is not a
    // declaration of absence while its snapshot lags the catalog.
    if (snapshot.catalog_generation < catalog.generation) return NegotiationOutcome::CatalogStale;
    return NegotiationOutcome::UnsupportedCapability;
  }
  if (declared->version >= requirement.min_version) return NegotiationOutcome::Satisfied;
  return NegotiationOutcome::VersionMismatch;
}

// ---------------------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------------------

JsonValue setting_value_to_json(const SettingValue& value) {
  JsonValue out = JsonValue::object();
  out.set_field("type", JsonValue::text(value.type_name()));
  switch (value.type) {
    case SettingValue::Type::Unset:
      break;
    case SettingValue::Type::Boolean:
      out.set_field("boolean", JsonValue::boolean(value.boolean));
      break;
    case SettingValue::Type::Integer:
      out.set_field("integer", JsonValue::integer(value.integer));
      break;
    case SettingValue::Type::Text:
      out.set_field("text", JsonValue::text(value.text));
      break;
  }
  return out;
}

Result<SettingValue> setting_value_from_json(const JsonValue& value) {
  auto type = value.require_string("type");
  if (!type) return Result<SettingValue>::failure(type.error);
  if (*type == "unset") return Result<SettingValue>::success(SettingValue::unset());
  if (*type == "boolean") {
    auto raw = value.require_bool("boolean");
    if (!raw) return Result<SettingValue>::failure(raw.error);
    return Result<SettingValue>::success(SettingValue::boolean_value(*raw));
  }
  if (*type == "integer") {
    auto raw = value.require_int("integer");
    if (!raw) return Result<SettingValue>::failure(raw.error);
    return Result<SettingValue>::success(SettingValue::integer_value(*raw));
  }
  if (*type == "text") {
    auto raw = value.require_string("text");
    if (!raw) return Result<SettingValue>::failure(raw.error);
    return Result<SettingValue>::success(SettingValue::text_value(*raw));
  }
  return Result<SettingValue>::failure(ErrorCode::MalformedInput, "unknown setting value type",
                                       escape_preview(*type));
}

JsonValue scope_to_json(const RuleScope& scope) {
  JsonValue::Array members;
  for (MemberId id : scope.members) members.push_back(JsonValue::text(id.to_string()));
  JsonValue::Array sites;
  for (SiteId id : scope.sites) sites.push_back(JsonValue::text(id.to_string()));
  return JsonValue::object({
      {"level", JsonValue::text(scope_level_name(scope.level))},
      {"members", JsonValue::array(std::move(members))},
      {"sites", JsonValue::array(std::move(sites))},
  });
}

Result<RuleScope> scope_from_json(const JsonValue& value) {
  auto level = value.require_string("level");
  if (!level) return Result<RuleScope>::failure(level.error);
  auto parsed_level = scope_level_from_name(*level);
  if (!parsed_level) return Result<RuleScope>::failure(parsed_level.error);
  RuleScope scope;
  scope.level = *parsed_level;
  auto members = value.require_array("members");
  if (!members) return Result<RuleScope>::failure(members.error);
  if ((*members)->size() > 4096) {
    return Result<RuleScope>::failure(ErrorCode::TooLarge, "scope carries too many member targets", {});
  }
  for (const JsonValue& item : (*members)->array_items()) {
    if (!item.is_string()) {
      return Result<RuleScope>::failure(ErrorCode::MalformedInput, "scope member identity is not a string", {});
    }
    auto id = MemberId::parse(item.as_string());
    if (!id) return Result<RuleScope>::failure(id.error);
    scope.members.push_back(*id);
  }
  auto sites = value.require_array("sites");
  if (!sites) return Result<RuleScope>::failure(sites.error);
  if ((*sites)->size() > 4096) {
    return Result<RuleScope>::failure(ErrorCode::TooLarge, "scope carries too many site targets", {});
  }
  for (const JsonValue& item : (*sites)->array_items()) {
    if (!item.is_string()) {
      return Result<RuleScope>::failure(ErrorCode::MalformedInput, "scope site identity is not a string", {});
    }
    auto id = SiteId::parse(item.as_string());
    if (!id) return Result<RuleScope>::failure(id.error);
    scope.sites.push_back(*id);
  }
  return Result<RuleScope>::success(scope);
}

JsonValue rule_to_json(const Rule& rule) {
  JsonValue::Array requirements;
  for (const auto& requirement : rule.capability_requirements) {
    requirements.push_back(JsonValue::object({
        {"capability", JsonValue::text(requirement.capability)},
        {"min_version", JsonValue::text(requirement.min_version.to_string())},
        {"optional", JsonValue::boolean(requirement.optional)},
    }));
  }
  return JsonValue::object({
      {"id", JsonValue::text(rule.id.to_string())},
      {"version", JsonValue::text(rule.version.to_string())},
      {"domain", JsonValue::text(rule.domain)},
      {"subject", JsonValue::text(rule.subject)},
      {"class", JsonValue::text(rule_class_name(rule.rule_class))},
      {"precedence", JsonValue::integer(static_cast<std::int64_t>(rule.precedence))},
      {"scope", scope_to_json(rule.scope)},
      {"value", setting_value_to_json(rule.value)},
      {"requires", JsonValue::array(std::move(requirements))},
      {"override", JsonValue::text(override_permission_name(rule.override_permission))},
      {"staleness", JsonValue::object({
          {"mode", JsonValue::text(staleness_mode_name(rule.staleness.mode))},
          {"max_staleness_ms", JsonValue::integer(rule.staleness.max_staleness_ms)},
      })},
      {"effective_from", JsonValue::integer(rule.effective_from.ms)},
      {"expires_at", JsonValue::integer(rule.expires_at.ms)},
      {"rationale", JsonValue::text(rule.rationale)},
  });
}

Result<Rule> rule_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<Rule>::failure(ErrorCode::MalformedInput, "rule must be a json object", {});
  }
  Rule rule;
  auto id = id_from_json<RuleId>(value, "id");
  if (!id) return Result<Rule>::failure(id.error);
  rule.id = *id;
  auto version = version_from_json(value, "version");
  if (!version) return Result<Rule>::failure(version.error);
  rule.version = *version;
  auto domain = value.require_string("domain");
  if (!domain) return Result<Rule>::failure(domain.error);
  rule.domain = *domain;
  auto subject = value.require_string("subject");
  if (!subject) return Result<Rule>::failure(subject.error);
  rule.subject = *subject;
  auto rule_class = value.require_string("class");
  if (!rule_class) return Result<Rule>::failure(rule_class.error);
  auto parsed_class = rule_class_from_name(*rule_class);
  if (!parsed_class) return Result<Rule>::failure(parsed_class.error);
  rule.rule_class = *parsed_class;
  if (const JsonValue* precedence = value.find("precedence")) {
    if (!precedence->is_int()) {
      return Result<Rule>::failure(ErrorCode::MalformedInput, "rule precedence is not an integer", {});
    }
    if (precedence->as_int() < 0 || precedence->as_int() > 1000000) {
      return Result<Rule>::failure(ErrorCode::InvalidArgument, "rule precedence is out of range", {});
    }
    rule.precedence = static_cast<std::uint32_t>(precedence->as_int());
  }
  auto scope = value.require_object("scope");
  if (!scope) return Result<Rule>::failure(scope.error);
  auto parsed_scope = scope_from_json(**scope);
  if (!parsed_scope) return Result<Rule>::failure(parsed_scope.error);
  rule.scope = *parsed_scope;
  auto setting = value.require_object("value");
  if (!setting) return Result<Rule>::failure(setting.error);
  auto parsed_value = setting_value_from_json(**setting);
  if (!parsed_value) return Result<Rule>::failure(parsed_value.error);
  rule.value = *parsed_value;
  if (const JsonValue* requirements_json = value.find("requires")) {
    if (!requirements_json->is_array()) {
      return Result<Rule>::failure(ErrorCode::MalformedInput, "rule requires is not an array", {});
    }
    if (requirements_json->size() > limits::kMaxCapabilityRequirementsPerRule) {
      return Result<Rule>::failure(ErrorCode::TooLarge, "rule declares too many capability requirements", {});
    }
    for (const JsonValue& item : requirements_json->array_items()) {
      CapabilityRequirement requirement;
      auto capability = item.require_string("capability");
      if (!capability) return Result<Rule>::failure(capability.error);
      requirement.capability = *capability;
      auto min_version = version_from_json(item, "min_version");
      if (!min_version) return Result<Rule>::failure(min_version.error);
      requirement.min_version = *min_version;
      if (const JsonValue* optional = item.find("optional")) {
        if (!optional->is_bool()) {
          return Result<Rule>::failure(ErrorCode::MalformedInput, "capability optional flag is not a boolean", {});
        }
        requirement.optional = optional->as_bool();
      }
      rule.capability_requirements.push_back(std::move(requirement));
    }
  }
  if (const JsonValue* permission = value.find("override")) {
    if (!permission->is_string()) {
      return Result<Rule>::failure(ErrorCode::MalformedInput, "rule override permission is not a string", {});
    }
    auto parsed = override_permission_from_name(permission->as_string());
    if (!parsed) return Result<Rule>::failure(parsed.error);
    rule.override_permission = *parsed;
  }
  if (const JsonValue* staleness = value.find("staleness")) {
    if (!staleness->is_object()) {
      return Result<Rule>::failure(ErrorCode::MalformedInput, "rule staleness is not an object", {});
    }
    auto mode = staleness->require_string("mode");
    if (!mode) return Result<Rule>::failure(mode.error);
    auto parsed_mode = staleness_mode_from_name(*mode);
    if (!parsed_mode) return Result<Rule>::failure(parsed_mode.error);
    rule.staleness.mode = *parsed_mode;
    auto window = staleness->require_int("max_staleness_ms");
    if (!window) return Result<Rule>::failure(window.error);
    rule.staleness.max_staleness_ms = *window;
  }
  if (value.contains("effective_from")) {
    auto parsed = timestamp_from_json(value, "effective_from");
    if (!parsed) return Result<Rule>::failure(parsed.error);
    rule.effective_from = *parsed;
  }
  if (value.contains("expires_at")) {
    auto parsed = timestamp_from_json(value, "expires_at");
    if (!parsed) return Result<Rule>::failure(parsed.error);
    rule.expires_at = *parsed;
  }
  if (const JsonValue* rationale = value.find("rationale")) {
    if (!rationale->is_string()) {
      return Result<Rule>::failure(ErrorCode::MalformedInput, "rule rationale is not a string", {});
    }
    rule.rationale = rationale->as_string();
  }
  auto status = validate_rule(rule);
  if (!status.ok()) return Result<Rule>::failure(status.error);
  return Result<Rule>::success(std::move(rule));
}

JsonValue bundle_to_json(const PolicyBundle& bundle) {
  JsonValue::Array rules;
  for (const Rule& rule : bundle.rules) rules.push_back(rule_to_json(rule));
  JsonValue::Array provenance;
  for (const ProvenanceEntry& entry : bundle.provenance) {
    provenance.push_back(JsonValue::object({
        {"actor", JsonValue::text(entry.actor)},
        {"member", JsonValue::text(entry.member.to_string())},
        {"grant", JsonValue::text(entry.grant.to_string())},
        {"authority_epoch", JsonValue::integer(static_cast<std::int64_t>(entry.authority_epoch.value))},
        {"generation", JsonValue::integer(static_cast<std::int64_t>(entry.generation.value))},
        {"at", JsonValue::integer(entry.at.ms)},
        {"previous", JsonValue::text(entry.previous.to_hex())},
        {"entry_digest", JsonValue::text(entry.entry_digest.to_hex())},
        {"note", JsonValue::text(entry.note)},
    }));
  }
  return JsonValue::object({
      {"id", JsonValue::text(bundle.id.to_string())},
      {"federation", JsonValue::text(bundle.federation.to_string())},
      {"global_generation", JsonValue::integer(static_cast<std::int64_t>(bundle.global_generation.value))},
      {"issuer_member", JsonValue::text(bundle.issuer_member.to_string())},
      {"scope", scope_to_json(bundle.scope)},
      {"issued_at", JsonValue::integer(bundle.issued_at.ms)},
      {"effective_from", JsonValue::integer(bundle.effective_from.ms)},
      {"expires_at", JsonValue::integer(bundle.expires_at.ms)},
      {"required_runtime", JsonValue::text(bundle.required_runtime.to_string())},
      {"capability_catalog_generation",
       JsonValue::integer(static_cast<std::int64_t>(bundle.capability_catalog_generation.value))},
      {"staleness", JsonValue::object({
          {"mode", JsonValue::text(staleness_mode_name(bundle.staleness.mode))},
          {"max_staleness_ms", JsonValue::integer(bundle.staleness.max_staleness_ms)},
      })},
      {"rules", JsonValue::array(std::move(rules))},
      {"provenance", JsonValue::array(std::move(provenance))},
      {"integrity_digest", JsonValue::text(bundle.integrity_digest.to_hex())},
      {"compatibility_digest", JsonValue::text(bundle.compatibility_digest.to_hex())},
  });
}

Result<PolicyBundle> bundle_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<PolicyBundle>::failure(ErrorCode::MalformedInput, "bundle must be a json object", {});
  }
  PolicyBundle bundle;
  auto id = id_from_json<PolicyBundleId>(value, "id");
  if (!id) return Result<PolicyBundle>::failure(id.error);
  bundle.id = *id;
  auto federation = id_from_json<FederationId>(value, "federation");
  if (!federation) return Result<PolicyBundle>::failure(federation.error);
  bundle.federation = *federation;
  auto generation = generation_from_json(value, "global_generation");
  if (!generation) return Result<PolicyBundle>::failure(generation.error);
  bundle.global_generation = *generation;
  auto issuer = id_from_json<MemberId>(value, "issuer_member");
  if (!issuer) return Result<PolicyBundle>::failure(issuer.error);
  bundle.issuer_member = *issuer;
  auto scope = value.require_object("scope");
  if (!scope) return Result<PolicyBundle>::failure(scope.error);
  auto parsed_scope = scope_from_json(**scope);
  if (!parsed_scope) return Result<PolicyBundle>::failure(parsed_scope.error);
  bundle.scope = *parsed_scope;
  auto issued_at = timestamp_from_json(value, "issued_at");
  if (!issued_at) return Result<PolicyBundle>::failure(issued_at.error);
  bundle.issued_at = *issued_at;
  auto effective_from = timestamp_from_json(value, "effective_from");
  if (!effective_from) return Result<PolicyBundle>::failure(effective_from.error);
  bundle.effective_from = *effective_from;
  auto expires_at = timestamp_from_json(value, "expires_at");
  if (!expires_at) return Result<PolicyBundle>::failure(expires_at.error);
  bundle.expires_at = *expires_at;
  auto runtime = version_from_json(value, "required_runtime");
  if (!runtime) return Result<PolicyBundle>::failure(runtime.error);
  bundle.required_runtime = *runtime;
  auto catalog_generation = generation_from_json(value, "capability_catalog_generation");
  if (!catalog_generation) return Result<PolicyBundle>::failure(catalog_generation.error);
  bundle.capability_catalog_generation = *catalog_generation;
  if (const JsonValue* staleness = value.find("staleness")) {
    if (!staleness->is_object()) {
      return Result<PolicyBundle>::failure(ErrorCode::MalformedInput, "bundle staleness is not an object", {});
    }
    auto mode = staleness->require_string("mode");
    if (!mode) return Result<PolicyBundle>::failure(mode.error);
    auto parsed_mode = staleness_mode_from_name(*mode);
    if (!parsed_mode) return Result<PolicyBundle>::failure(parsed_mode.error);
    bundle.staleness.mode = *parsed_mode;
    auto window = staleness->require_int("max_staleness_ms");
    if (!window) return Result<PolicyBundle>::failure(window.error);
    bundle.staleness.max_staleness_ms = *window;
  }
  auto rules = value.require_array("rules");
  if (!rules) return Result<PolicyBundle>::failure(rules.error);
  if ((*rules)->size() > limits::kMaxRulesPerBundle) {
    return Result<PolicyBundle>::failure(ErrorCode::TooLarge, "bundle carries too many rules", {});
  }
  for (const JsonValue& item : (*rules)->array_items()) {
    auto rule = rule_from_json(item);
    if (!rule) return Result<PolicyBundle>::failure(rule.error);
    bundle.rules.push_back(std::move(*rule.value));
  }
  auto provenance = value.require_array("provenance");
  if (!provenance) return Result<PolicyBundle>::failure(provenance.error);
  if ((*provenance)->size() > limits::kMaxProvenanceEntries) {
    return Result<PolicyBundle>::failure(ErrorCode::TooLarge, "provenance chain exceeds the length limit", {});
  }
  for (const JsonValue& item : (*provenance)->array_items()) {
    ProvenanceEntry entry;
    auto actor = item.require_string("actor");
    if (!actor) return Result<PolicyBundle>::failure(actor.error);
    entry.actor = *actor;
    auto member = id_from_json<MemberId>(item, "member");
    if (!member) return Result<PolicyBundle>::failure(member.error);
    entry.member = *member;
    auto grant = id_from_json<GrantId>(item, "grant");
    if (!grant) return Result<PolicyBundle>::failure(grant.error);
    entry.grant = *grant;
    auto epoch = item.require_int_in_range("authority_epoch", 0, INT64_MAX);
    if (!epoch) return Result<PolicyBundle>::failure(epoch.error);
    entry.authority_epoch = Epoch{static_cast<std::uint64_t>(*epoch)};
    auto entry_generation = generation_from_json(item, "generation");
    if (!entry_generation) return Result<PolicyBundle>::failure(entry_generation.error);
    entry.generation = *entry_generation;
    auto at = timestamp_from_json(item, "at");
    if (!at) return Result<PolicyBundle>::failure(at.error);
    entry.at = *at;
    auto previous = digest_from_json(item, "previous");
    if (!previous) return Result<PolicyBundle>::failure(previous.error);
    entry.previous = *previous;
    auto entry_digest = digest_from_json(item, "entry_digest");
    if (!entry_digest) return Result<PolicyBundle>::failure(entry_digest.error);
    entry.entry_digest = *entry_digest;
    auto note = item.require_string("note");
    if (!note) return Result<PolicyBundle>::failure(note.error);
    entry.note = *note;
    bundle.provenance.push_back(std::move(entry));
  }
  auto integrity = digest_from_json(value, "integrity_digest");
  if (!integrity) return Result<PolicyBundle>::failure(integrity.error);
  bundle.integrity_digest = *integrity;
  auto compatibility = digest_from_json(value, "compatibility_digest");
  if (!compatibility) return Result<PolicyBundle>::failure(compatibility.error);
  bundle.compatibility_digest = *compatibility;
  auto status = verify_bundle(bundle);
  if (!status.ok()) return Result<PolicyBundle>::failure(status.error);
  return Result<PolicyBundle>::success(std::move(bundle));
}

JsonValue override_to_json(const LocalOverride& override_record) {
  return JsonValue::object({
      {"id", JsonValue::text(override_record.id.to_string())},
      {"federation", JsonValue::text(override_record.federation.to_string())},
      {"site", JsonValue::text(override_record.site.to_string())},
      {"member", JsonValue::text(override_record.member.to_string())},
      {"domain", JsonValue::text(override_record.domain)},
      {"subject", JsonValue::text(override_record.subject)},
      {"target_rule", JsonValue::text(override_record.target_rule.to_string())},
      {"target_rule_digest", JsonValue::text(override_record.target_rule_digest.to_hex())},
      {"target_bundle", JsonValue::text(override_record.target_bundle.to_string())},
      {"target_bundle_generation",
       JsonValue::integer(static_cast<std::int64_t>(override_record.target_bundle_generation.value))},
      {"target_bundle_digest", JsonValue::text(override_record.target_bundle_digest.to_hex())},
      {"local_generation", JsonValue::integer(static_cast<std::int64_t>(override_record.local_generation.value))},
      {"value", setting_value_to_json(override_record.value)},
      {"authority", JsonValue::text(override_record.authority.to_string())},
      {"author", JsonValue::text(override_record.author)},
      {"reason", JsonValue::text(override_record.reason)},
      {"created_at", JsonValue::integer(override_record.created_at.ms)},
      {"expires_at", JsonValue::integer(override_record.expires_at.ms)},
      {"digest", JsonValue::text(override_record.digest.to_hex())},
  });
}

Result<LocalOverride> override_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<LocalOverride>::failure(ErrorCode::MalformedInput, "override must be a json object", {});
  }
  LocalOverride record;
  auto id = id_from_json<OverrideId>(value, "id");
  if (!id) return Result<LocalOverride>::failure(id.error);
  record.id = *id;
  auto federation = id_from_json<FederationId>(value, "federation");
  if (!federation) return Result<LocalOverride>::failure(federation.error);
  record.federation = *federation;
  auto site = id_from_json<SiteId>(value, "site");
  if (!site) return Result<LocalOverride>::failure(site.error);
  record.site = *site;
  auto member = id_from_json<MemberId>(value, "member");
  if (!member) return Result<LocalOverride>::failure(member.error);
  record.member = *member;
  auto domain = value.require_string("domain");
  if (!domain) return Result<LocalOverride>::failure(domain.error);
  record.domain = *domain;
  auto subject = value.require_string("subject");
  if (!subject) return Result<LocalOverride>::failure(subject.error);
  record.subject = *subject;
  auto target_rule = id_from_json<RuleId>(value, "target_rule");
  if (!target_rule) return Result<LocalOverride>::failure(target_rule.error);
  record.target_rule = *target_rule;
  auto rule_digest = digest_from_json(value, "target_rule_digest");
  if (!rule_digest) return Result<LocalOverride>::failure(rule_digest.error);
  record.target_rule_digest = *rule_digest;
  auto target_bundle = id_from_json<PolicyBundleId>(value, "target_bundle");
  if (!target_bundle) return Result<LocalOverride>::failure(target_bundle.error);
  record.target_bundle = *target_bundle;
  auto bundle_generation = generation_from_json(value, "target_bundle_generation");
  if (!bundle_generation) return Result<LocalOverride>::failure(bundle_generation.error);
  record.target_bundle_generation = *bundle_generation;
  auto bundle_digest = digest_from_json(value, "target_bundle_digest");
  if (!bundle_digest) return Result<LocalOverride>::failure(bundle_digest.error);
  record.target_bundle_digest = *bundle_digest;
  auto local_generation = generation_from_json(value, "local_generation");
  if (!local_generation) return Result<LocalOverride>::failure(local_generation.error);
  record.local_generation = *local_generation;
  auto setting = value.require_object("value");
  if (!setting) return Result<LocalOverride>::failure(setting.error);
  auto parsed_value = setting_value_from_json(**setting);
  if (!parsed_value) return Result<LocalOverride>::failure(parsed_value.error);
  record.value = *parsed_value;
  auto authority = id_from_json<GrantId>(value, "authority");
  if (!authority) return Result<LocalOverride>::failure(authority.error);
  record.authority = *authority;
  auto author = value.require_string("author");
  if (!author) return Result<LocalOverride>::failure(author.error);
  record.author = *author;
  auto reason = value.require_string("reason");
  if (!reason) return Result<LocalOverride>::failure(reason.error);
  record.reason = *reason;
  auto created_at = timestamp_from_json(value, "created_at");
  if (!created_at) return Result<LocalOverride>::failure(created_at.error);
  record.created_at = *created_at;
  auto expires_at = timestamp_from_json(value, "expires_at");
  if (!expires_at) return Result<LocalOverride>::failure(expires_at.error);
  record.expires_at = *expires_at;
  auto digest = digest_from_json(value, "digest");
  if (!digest) return Result<LocalOverride>::failure(digest.error);
  record.digest = *digest;
  auto status = validate_override(record);
  if (!status.ok()) return Result<LocalOverride>::failure(status.error);
  auto computed = compute_override_digest(record);
  if (!computed) return Result<LocalOverride>::failure(computed.error);
  if (*computed != record.digest) {
    return Result<LocalOverride>::failure(ErrorCode::IntegrityFailure,
                                          "override digest does not match content");
  }
  return Result<LocalOverride>::success(std::move(record));
}

JsonValue capability_catalog_to_json(const CapabilityCatalog& catalog) {
  JsonValue::Array entries;
  for (const auto& entry : catalog.capabilities) {
    entries.push_back(JsonValue::object({
        {"capability", JsonValue::text(entry.capability)},
        {"version", JsonValue::text(entry.version.to_string())},
    }));
  }
  return JsonValue::object({
      {"generation", JsonValue::integer(static_cast<std::int64_t>(catalog.generation.value))},
      {"capabilities", JsonValue::array(std::move(entries))},
  });
}

Result<CapabilityCatalog> capability_catalog_from_json(const JsonValue& value) {
  CapabilityCatalog catalog;
  auto generation = generation_from_json(value, "generation");
  if (!generation) return Result<CapabilityCatalog>::failure(generation.error);
  catalog.generation = *generation;
  auto entries = value.require_array("capabilities");
  if (!entries) return Result<CapabilityCatalog>::failure(entries.error);
  for (const JsonValue& item : (*entries)->array_items()) {
    CapabilityRef entry;
    auto capability = item.require_string("capability");
    if (!capability) return Result<CapabilityCatalog>::failure(capability.error);
    entry.capability = *capability;
    auto version = version_from_json(item, "version");
    if (!version) return Result<CapabilityCatalog>::failure(version.error);
    entry.version = *version;
    catalog.capabilities.push_back(std::move(entry));
  }
  auto status = validate_capability_catalog(catalog);
  if (!status.ok()) return Result<CapabilityCatalog>::failure(status.error);
  return Result<CapabilityCatalog>::success(std::move(catalog));
}

JsonValue capability_snapshot_to_json(const CapabilitySnapshot& snapshot) {
  JsonValue::Array entries;
  for (const auto& entry : snapshot.capabilities) {
    entries.push_back(JsonValue::object({
        {"capability", JsonValue::text(entry.capability)},
        {"version", JsonValue::text(entry.version.to_string())},
    }));
  }
  return JsonValue::object({
      {"catalog_generation", JsonValue::integer(static_cast<std::int64_t>(snapshot.catalog_generation.value))},
      {"capabilities", JsonValue::array(std::move(entries))},
  });
}

Result<CapabilitySnapshot> capability_snapshot_from_json(const JsonValue& value) {
  CapabilitySnapshot snapshot;
  auto generation = generation_from_json(value, "catalog_generation");
  if (!generation) return Result<CapabilitySnapshot>::failure(generation.error);
  snapshot.catalog_generation = *generation;
  auto entries = value.require_array("capabilities");
  if (!entries) return Result<CapabilitySnapshot>::failure(entries.error);
  for (const JsonValue& item : (*entries)->array_items()) {
    CapabilityRef entry;
    auto capability = item.require_string("capability");
    if (!capability) return Result<CapabilitySnapshot>::failure(capability.error);
    entry.capability = *capability;
    auto version = version_from_json(item, "version");
    if (!version) return Result<CapabilitySnapshot>::failure(version.error);
    entry.version = *version;
    snapshot.capabilities.push_back(std::move(entry));
  }
  auto status = validate_capability_snapshot(snapshot);
  if (!status.ok()) return Result<CapabilitySnapshot>::failure(status.error);
  return Result<CapabilitySnapshot>::success(std::move(snapshot));
}

}  // namespace gpf
