#pragma once
// Deterministic fixture builders shared by the Global Policy Federation test suites.

#include "gpf/authority.hpp"
#include "gpf/base.hpp"
#include "gpf/effective.hpp"
#include "gpf/policy.hpp"

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace gpf_test {

using namespace gpf;

inline constexpr std::int64_t kSecond = 1000;
inline constexpr std::int64_t kMinute = 60 * kSecond;
inline constexpr std::int64_t kHour = 60 * kMinute;
inline constexpr std::int64_t kDay = 24 * kHour;

inline Timestamp at(std::int64_t millis) { return Timestamp{millis}; }

inline FederationId make_federation(IdGenerator& ids) {
  FederationId id;
  id.value = ids.next();
  return id;
}

inline MemberId make_member(IdGenerator& ids) {
  MemberId id;
  id.value = ids.next();
  return id;
}

inline SiteId make_site(IdGenerator& ids) {
  SiteId id;
  id.value = ids.next();
  return id;
}

inline RuleId make_rule_id(IdGenerator& ids) {
  RuleId id;
  id.value = ids.next();
  return id;
}

inline PolicyBundleId make_bundle_id(IdGenerator& ids) {
  PolicyBundleId id;
  id.value = ids.next();
  return id;
}

inline GrantId make_grant_id(IdGenerator& ids) {
  GrantId id;
  id.value = ids.next();
  return id;
}

inline OverrideId make_override_id(IdGenerator& ids) {
  OverrideId id;
  id.value = ids.next();
  return id;
}

inline RevocationId make_revocation_id(IdGenerator& ids) {
  RevocationId id;
  id.value = ids.next();
  return id;
}

inline SettingValue int_value(std::int64_t value) { return SettingValue::integer_value(value); }
inline SettingValue bool_value(bool value) { return SettingValue::boolean_value(value); }
inline SettingValue text_value(const std::string& value) { return SettingValue::text_value(value); }

inline Rule make_rule(IdGenerator& ids, const std::string& domain, const std::string& subject,
                      SettingValue value, RuleClass rule_class = RuleClass::Default,
                      RuleScope scope = RuleScope::federation(), std::uint32_t precedence = 0,
                      SemanticVersion version = SemanticVersion{1, 0, 0}) {
  Rule rule;
  rule.id = make_rule_id(ids);
  rule.version = version;
  rule.domain = domain;
  rule.subject = subject;
  rule.rule_class = rule_class;
  rule.precedence = precedence;
  rule.scope = std::move(scope);
  rule.value = std::move(value);
  rule.override_permission = rule_class == RuleClass::Mandatory ? OverridePermission::Allowed
                                                               : OverridePermission::Allowed;
  return rule;
}

inline ProvenanceEntry make_provenance(const std::string& actor, MemberId member, GrantId grant,
                                       Epoch epoch, Generation generation, Timestamp when,
                                       const Digest& previous, const std::string& note = {}) {
  ProvenanceEntry entry;
  entry.actor = actor;
  entry.member = member;
  entry.grant = grant;
  entry.authority_epoch = epoch;
  entry.generation = generation;
  entry.at = when;
  entry.previous = previous;
  entry.note = note;
  auto digest = compute_provenance_digest(entry);
  entry.entry_digest = *digest;
  return entry;
}

inline PolicyBundle make_bundle(IdGenerator& ids, FederationId federation, MemberId issuer,
                                Generation generation, std::vector<Rule> rules,
                                Timestamp issued_at, RuleScope scope = RuleScope::federation(),
                                StalenessPolicy staleness = StalenessPolicy::require_fresh(),
                                SemanticVersion required_runtime = SemanticVersion{1, 0, 0},
                                Generation catalog_generation = Generation{1},
                                std::string actor = "testsuite",
                                PolicyBundleId forced_id = PolicyBundleId{}) {
  PolicyBundle bundle;
  bundle.id = forced_id.is_nil() ? make_bundle_id(ids) : forced_id;
  bundle.federation = federation;
  bundle.global_generation = generation;
  bundle.issuer_member = issuer;
  bundle.scope = std::move(scope);
  bundle.issued_at = issued_at;
  bundle.effective_from = issued_at;
  bundle.required_runtime = required_runtime;
  bundle.capability_catalog_generation = catalog_generation;
  bundle.staleness = staleness;
  bundle.rules = std::move(rules);
  bundle.provenance.push_back(make_provenance(actor, issuer, GrantId{}, Epoch{1}, generation,
                                              issued_at, Digest{}, "initial publication"));
  normalize_bundle(bundle);
  auto sealed = seal_bundle(bundle);
  (void)sealed;
  return bundle;
}

inline PolicyBundle make_bundle_with_provenance(IdGenerator& ids, FederationId federation,
                                                MemberId issuer, Generation generation,
                                                std::vector<Rule> rules, Timestamp issued_at,
                                                std::string actor, GrantId grant,
                                                const Digest& previous,
                                                RuleScope scope = RuleScope::federation(),
                                                StalenessPolicy staleness =
                                                    StalenessPolicy::require_fresh()) {
  PolicyBundle bundle;
  bundle.id = make_bundle_id(ids);
  bundle.federation = federation;
  bundle.global_generation = generation;
  bundle.issuer_member = issuer;
  bundle.scope = std::move(scope);
  bundle.issued_at = issued_at;
  bundle.effective_from = issued_at;
  bundle.required_runtime = SemanticVersion{1, 0, 0};
  bundle.capability_catalog_generation = Generation{1};
  bundle.staleness = staleness;
  bundle.rules = std::move(rules);
  bundle.provenance.push_back(make_provenance(actor, issuer, grant, Epoch{1}, generation, issued_at,
                                              previous, "publication"));
  normalize_bundle(bundle);
  auto sealed = seal_bundle(bundle);
  (void)sealed;
  return bundle;
}

inline AuthorityGrant make_grant(IdGenerator& ids, FederationId federation, MemberId grantor,
                                 MemberId grantee, GrantId parent, AuthorityAction action,
                                 RuleScope scope, std::vector<std::string> domains = {},
                                 Timestamp not_before = at(0), Timestamp not_after = at(0),
                                 Epoch epoch = Epoch{}, const std::string& justification = "test") {
  AuthorityGrant grant;
  grant.id = make_grant_id(ids);
  grant.federation = federation;
  grant.grantor = grantor;
  grant.grantee = grantee;
  grant.parent = parent;
  grant.action = action;
  grant.scope = std::move(scope);
  grant.conflict_domains = std::move(domains);
  grant.not_before = not_before;
  grant.not_after = not_after;
  grant.authority_epoch = epoch;
  grant.justification = justification;
  auto sealed = seal_grant(grant);
  (void)sealed;
  return grant;
}

inline RevocationRecord make_revocation(IdGenerator& ids, FederationId federation,
                                        RevocationTarget target, Id128 target_id,
                                        MemberId actor_member, const std::string& actor,
                                        GrantId authority, std::uint64_t sequence,
                                        Timestamp issued_at,
                                        const std::string& reason = "test revocation") {
  RevocationRecord record;
  record.id = make_revocation_id(ids);
  record.federation = federation;
  record.target = target;
  record.target_id = target_id;
  record.actor_member = actor_member;
  record.actor = actor;
  record.authority = authority;
  record.sequence = SequenceNumber{sequence};
  record.issued_at = issued_at;
  record.effective_at = issued_at;
  record.reason = reason;
  auto sealed = seal_revocation(record);
  (void)sealed;
  return record;
}

inline LocalOverride make_override(IdGenerator& ids, FederationId federation, MemberId member,
                                   SiteId site, const Rule& rule, const PolicyBundle& bundle,
                                   Generation local_generation, SettingValue value,
                                   const std::string& author, const std::string& reason,
                                   GrantId authority = GrantId{}, Timestamp created_at = at(0),
                                   Timestamp expires_at = at(0)) {
  LocalOverride record;
  record.id = make_override_id(ids);
  record.federation = federation;
  record.member = member;
  record.site = site;
  record.domain = rule.domain;
  record.subject = rule.subject;
  record.target_rule = rule.id;
  record.target_rule_digest = *compute_rule_digest(rule);
  record.target_bundle = bundle.id;
  record.target_bundle_generation = bundle.global_generation;
  record.target_bundle_digest = bundle.integrity_digest;
  record.local_generation = local_generation;
  record.value = std::move(value);
  record.authority = authority;
  record.author = author;
  record.reason = reason;
  record.created_at = created_at;
  record.expires_at = expires_at;
  auto sealed = seal_override(record);
  (void)sealed;
  return record;
}

inline CapabilityCatalog make_catalog(Generation generation,
                                      std::vector<std::pair<std::string, SemanticVersion>> entries) {
  CapabilityCatalog catalog;
  catalog.generation = generation;
  for (auto& entry : entries) {
    catalog.capabilities.push_back(CapabilityRef{entry.first, entry.second});
  }
  return catalog;
}

inline SiteCapabilitySnapshot make_snapshot(
    Generation catalog_generation,
    std::vector<std::pair<std::string, SemanticVersion>> entries) {
  SiteCapabilitySnapshot snapshot;
  snapshot.catalog_generation = catalog_generation;
  for (auto& entry : entries) {
    snapshot.capabilities.push_back(CapabilityRef{entry.first, entry.second});
  }
  return snapshot;
}


// A private temporary directory that removes itself, so no scratch state survives a test run.
class TempDirectory {
 public:
  explicit TempDirectory(const std::string& label) {
    static int counter = 0;
    ++counter;
    path_ = std::filesystem::temp_directory_path() /
            ("gpf-test-" + label + "-" + std::to_string(counter));
    std::error_code error;
    std::filesystem::remove_all(path_, error);
    std::filesystem::create_directories(path_, error);
  }
  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;
  const std::filesystem::path& path() const { return path_; }
  std::filesystem::path child(const std::string& name) const { return path_ / name; }

 private:
  std::filesystem::path path_;
};

// Site-level fixture used by compiler, runtime and end-to-end tests.
struct SiteFixture {
  IdGenerator ids;
  FederationId federation;
  MemberId operator_member;
  MemberId second_operator_member;
  MemberId member;
  SiteId site;
  Timestamp now;
  MembershipBinding membership;

  explicit SiteFixture(std::uint64_t seed = 4242, Timestamp now_in = at(100 * kDay))
      : ids(seed), federation(make_federation(ids)), operator_member(make_member(ids)),
        second_operator_member(make_member(ids)), member(make_member(ids)), site(make_site(ids)),
        now(now_in) {
    membership.entries.push_back(std::make_pair(member, site));
  }

  CapabilityCatalog catalog(Generation generation,
                            std::vector<std::pair<std::string, SemanticVersion>> entries) const {
    return make_catalog(generation, std::move(entries));
  }

  SiteCapabilitySnapshot snapshot(
      Generation catalog_generation,
      std::vector<std::pair<std::string, SemanticVersion>> entries) const {
    return make_snapshot(catalog_generation, std::move(entries));
  }

  PolicyBundle global_bundle(std::vector<Rule> rules, Generation generation,
                             StalenessPolicy staleness = StalenessPolicy::require_fresh(),
                             Timestamp issued = Timestamp{0},
                             SemanticVersion required_runtime = SemanticVersion{1, 0, 0},
                             Generation catalog_generation = Generation{1},
                             RuleScope scope = RuleScope::federation(),
                             MemberId issuer = MemberId{}) {
    const Timestamp when = issued.ms == 0 ? now : issued;
    const MemberId who = issuer.is_nil() ? operator_member : issuer;
    return make_bundle(ids, federation, who, generation, std::move(rules), when, std::move(scope),
                       staleness, required_runtime, catalog_generation, "federation-operator");
  }

  PolicyBundle local_bundle(std::vector<Rule> rules, Generation generation,
                            Timestamp issued = Timestamp{0}) {
    const Timestamp when = issued.ms == 0 ? now : issued;
    return make_bundle(ids, federation, member, generation, std::move(rules), when,
                       RuleScope::for_sites({site}), StalenessPolicy::require_fresh(),
                       SemanticVersion{1, 0, 0}, Generation{1}, "site-operator");
  }

  static constexpr const char* kMetering = "power.metering";
  static constexpr const char* kLiquid = "cooling.liquid";

  // A site view that already knows the catalog generation bundles are authored against.
  EffectivePolicyInput input() const {
    EffectivePolicyInput in;
    in.federation = federation;
    in.member = member;
    in.site = site;
    in.now = now;
    in.runtime_version = SemanticVersion{1, 0, 0};
    in.capability_catalog =
        make_catalog(Generation{1}, {{kMetering, SemanticVersion{2, 1, 0}},
                                     {kLiquid, SemanticVersion{1, 0, 0}}});
    in.capabilities = make_snapshot(Generation{1}, {{kMetering, SemanticVersion{2, 1, 0}},
                                                    {kLiquid, SemanticVersion{1, 0, 0}}});
    return in;
  }
};

// Finds the effective entry or returns an Absent entry.
inline EffectiveEntry entry_or_absent(const EffectivePolicy& policy, const std::string& domain,
                                      const std::string& subject) {
  return explain_subject(policy, domain, subject);
}

}  // namespace gpf_test