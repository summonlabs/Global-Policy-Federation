#include "gpf/plan.hpp"

#include "gpf/platform.hpp"

#include <algorithm>
#include <random>
#include <set>

namespace gpf {
namespace {

Status invalid(std::string message, std::string detail = {}) {
  return Status::failure(ErrorCode::InvalidArgument, std::move(message), std::move(detail));
}

ProvenanceEntry chain_entry(const std::string& actor, MemberId member, GrantId grant,
                            Generation generation, Timestamp at, const Digest& previous,
                            const std::string& note) {
  ProvenanceEntry entry;
  entry.actor = actor;
  entry.member = member;
  entry.grant = grant;
  entry.authority_epoch = Epoch{};
  entry.generation = generation;
  entry.at = at;
  entry.previous = previous;
  entry.note = note;
  entry.entry_digest = *compute_provenance_digest(entry);
  return entry;
}

PolicyBundle seal_plan_bundle(IdGenerator& ids, FederationId federation, MemberId issuer,
                              Generation generation, RuleScope scope, std::vector<Rule> rules,
                              Timestamp issued_at, StalenessPolicy staleness,
                              Generation catalog_generation, const std::string& actor) {
  PolicyBundle bundle;
  bundle.id.value = ids.next();
  bundle.federation = federation;
  bundle.global_generation = generation;
  bundle.issuer_member = issuer;
  bundle.scope = std::move(scope);
  bundle.issued_at = issued_at;
  bundle.effective_from = issued_at;
  bundle.required_runtime = SemanticVersion{1, 0, 0};
  bundle.capability_catalog_generation = catalog_generation;
  bundle.staleness = staleness;
  bundle.rules = std::move(rules);
  bundle.provenance.push_back(
      chain_entry(actor, issuer, GrantId{}, generation, issued_at, Digest{}, "scenario publication"));
  normalize_bundle(bundle);
  const Status sealed = seal_bundle(bundle);
  (void)sealed;
  return bundle;
}

Rule make_plan_rule(IdGenerator& ids, const std::string& domain, const std::string& subject,
                    SettingValue value, RuleClass rule_class,
                    RuleScope scope = RuleScope::federation(), std::uint32_t precedence = 0) {
  Rule rule;
  rule.id.value = ids.next();
  rule.version = SemanticVersion{1, 0, 0};
  rule.domain = domain;
  rule.subject = subject;
  rule.rule_class = rule_class;
  rule.precedence = precedence;
  rule.scope = std::move(scope);
  rule.value = std::move(value);
  rule.override_permission = OverridePermission::Allowed;
  return rule;
}

AuthorityGrant make_plan_grant(IdGenerator& ids, FederationId federation, MemberId grantor,
                               MemberId grantee, GrantId parent, AuthorityAction action,
                               RuleScope scope, std::vector<std::string> domains) {
  AuthorityGrant grant;
  grant.id.value = ids.next();
  grant.federation = federation;
  grant.grantor = grantor;
  grant.grantee = grantee;
  grant.parent = parent;
  grant.action = action;
  grant.scope = std::move(scope);
  grant.conflict_domains = std::move(domains);
  grant.authority_epoch = Epoch{};
  grant.justification = "federation scenario delegation";
  const Status sealed = seal_grant(grant);
  (void)sealed;
  return grant;
}

}  // namespace

Status validate_plan(const FederationPlan& plan) {
  if (plan.format_version != kPlanFormatVersion) {
    return Status::failure(ErrorCode::UnsupportedFormat, "unsupported plan format version",
                           std::to_string(plan.format_version));
  }
  if (plan.federation.is_nil()) return invalid("plan has no federation identity");
  if (plan.root_member.is_nil()) return invalid("plan has no root member");
  if (plan.coordinator_site.is_nil()) return invalid("plan has no coordinator site");
  auto catalog_status = validate_capability_catalog(plan.catalog);
  if (!catalog_status.ok()) return catalog_status;
  auto membership_status = validate_membership_binding(plan.membership);
  if (!membership_status.ok()) return membership_status;
  if (plan.grants.size() > limits::kMaxGrantsPerFederation) {
    return Status::failure(ErrorCode::TooLarge, "plan carries too many grants");
  }
  bool root_seen = false;
  for (const AuthorityGrant& grant : plan.grants) {
    auto status = validate_grant(grant);
    if (!status.ok()) return status;
    if (grant.federation != plan.federation) {
      return invalid("plan carries a grant for another federation", grant.id.to_string());
    }
    if (grant.parent.is_nil()) {
      if (root_seen) return invalid("plan carries more than one root grant");
      root_seen = true;
    }
  }
  if (plan.bundles.size() > limits::kMaxBundlesPerFederation) {
    return Status::failure(ErrorCode::TooLarge, "plan carries too many bundles");
  }
  for (const PolicyBundle& bundle : plan.bundles) {
    auto status = verify_bundle(bundle);
    if (!status.ok()) return status;
    if (bundle.federation != plan.federation) {
      return invalid("plan carries a bundle for another federation", bundle.id.to_string());
    }
  }
  if (plan.revocations.size() > limits::kMaxRevocations) {
    return Status::failure(ErrorCode::TooLarge, "plan carries too many revocations");
  }
  std::set<std::string> sites;
  for (const PlanSite& entry : plan.sites) {
    if (entry.member.is_nil() || entry.site.is_nil()) return invalid("plan carries an empty site entry");
    if (!sites.insert(entry.site.to_string()).second) {
      return Status::failure(ErrorCode::DuplicateIdentity, "plan repeats a site identity",
                             entry.site.to_string());
    }
  }
  return Status::success();
}

JsonValue plan_to_json(const FederationPlan& plan) {
  JsonValue::Array grants;
  for (const AuthorityGrant& grant : plan.grants) grants.push_back(grant_to_json(grant));
  JsonValue::Array bundles;
  for (const PolicyBundle& bundle : plan.bundles) bundles.push_back(bundle_to_json(bundle));
  JsonValue::Array revocations;
  for (const RevocationRecord& record : plan.revocations) revocations.push_back(revocation_to_json(record));
  JsonValue::Array sites;
  for (const PlanSite& entry : plan.sites) {
    sites.push_back(JsonValue::object({
        {"member", JsonValue::text(entry.member.to_string())},
        {"site", JsonValue::text(entry.site.to_string())},
    }));
  }
  JsonValue::Array membership;
  for (const auto& entry : plan.membership.entries) {
    membership.push_back(JsonValue::object({
        {"member", JsonValue::text(entry.first.to_string())},
        {"site", JsonValue::text(entry.second.to_string())},
    }));
  }
  return JsonValue::object({
      {"format_version", JsonValue::integer(static_cast<std::int64_t>(plan.format_version))},
      {"federation", JsonValue::text(plan.federation.to_string())},
      {"root_member", JsonValue::text(plan.root_member.to_string())},
      {"coordinator_site", JsonValue::text(plan.coordinator_site.to_string())},
      {"catalog", capability_catalog_to_json(plan.catalog)},
      {"membership", JsonValue::array(std::move(membership))},
      {"grants", JsonValue::array(std::move(grants))},
      {"bundles", JsonValue::array(std::move(bundles))},
      {"revocations", JsonValue::array(std::move(revocations))},
      {"sites", JsonValue::array(std::move(sites))},
  });
}

Result<FederationPlan> plan_from_json(const JsonValue& value) {
  if (!value.is_object()) {
    return Result<FederationPlan>::failure(ErrorCode::MalformedInput, "plan must be a json object");
  }
  FederationPlan plan;
  auto format = value.require_int_in_range("format_version", 1, 1000);
  if (!format) return Result<FederationPlan>::failure(format.error);
  plan.format_version = static_cast<std::uint32_t>(*format);
  auto federation = value.require_string("federation");
  if (!federation) return Result<FederationPlan>::failure(federation.error);
  auto parsed_federation = FederationId::parse(*federation);
  if (!parsed_federation) return Result<FederationPlan>::failure(parsed_federation.error);
  plan.federation = *parsed_federation;
  auto root_member = value.require_string("root_member");
  if (!root_member) return Result<FederationPlan>::failure(root_member.error);
  auto parsed_root = MemberId::parse(*root_member);
  if (!parsed_root) return Result<FederationPlan>::failure(parsed_root.error);
  plan.root_member = *parsed_root;
  auto coordinator = value.require_string("coordinator_site");
  if (!coordinator) return Result<FederationPlan>::failure(coordinator.error);
  auto parsed_coordinator = SiteId::parse(*coordinator);
  if (!parsed_coordinator) return Result<FederationPlan>::failure(parsed_coordinator.error);
  plan.coordinator_site = *parsed_coordinator;

  auto catalog = value.require_object("catalog");
  if (!catalog) return Result<FederationPlan>::failure(catalog.error);
  auto parsed_catalog = capability_catalog_from_json(**catalog);
  if (!parsed_catalog) return Result<FederationPlan>::failure(parsed_catalog.error);
  plan.catalog = std::move(*parsed_catalog.value);

  auto membership = value.require_array("membership");
  if (!membership) return Result<FederationPlan>::failure(membership.error);
  for (const JsonValue& item : (*membership)->array_items()) {
    auto member = item.require_string("member");
    if (!member) return Result<FederationPlan>::failure(member.error);
    auto parsed_member = MemberId::parse(*member);
    if (!parsed_member) return Result<FederationPlan>::failure(parsed_member.error);
    auto site = item.require_string("site");
    if (!site) return Result<FederationPlan>::failure(site.error);
    auto parsed_site = SiteId::parse(*site);
    if (!parsed_site) return Result<FederationPlan>::failure(parsed_site.error);
    plan.membership.entries.emplace_back(*parsed_member, *parsed_site);
  }

  const auto decode_array = [&](const char* key, std::size_t limit, auto&& decode,
                                auto&& push) -> Status {
    auto items = value.require_array(key);
    if (!items) return Status::failure(items.error);
    if ((*items)->size() > limit) {
      return Status::failure(ErrorCode::TooLarge, "plan array exceeds the limit", key);
    }
    for (const JsonValue& item : (*items)->array_items()) {
      auto decoded = decode(item);
      if (!decoded) return Status::failure(decoded.error);
      push(std::move(*decoded.value));
    }
    return Status::success();
  };

  Status status = decode_array(
      "grants", limits::kMaxGrantsPerFederation,
      [](const JsonValue& item) { return grant_from_json(item); },
      [&](AuthorityGrant grant) { plan.grants.push_back(std::move(grant)); });
  if (!status.ok()) return Result<FederationPlan>::failure(status.error);
  status = decode_array(
      "bundles", limits::kMaxBundlesPerFederation,
      [](const JsonValue& item) { return bundle_from_json(item); },
      [&](PolicyBundle bundle) { plan.bundles.push_back(std::move(bundle)); });
  if (!status.ok()) return Result<FederationPlan>::failure(status.error);
  status = decode_array(
      "revocations", limits::kMaxRevocations,
      [](const JsonValue& item) { return revocation_from_json(item); },
      [&](RevocationRecord record) { plan.revocations.push_back(std::move(record)); });
  if (!status.ok()) return Result<FederationPlan>::failure(status.error);

  auto sites = value.require_array("sites");
  if (!sites) return Result<FederationPlan>::failure(sites.error);
  for (const JsonValue& item : (*sites)->array_items()) {
    PlanSite entry;
    auto member = item.require_string("member");
    if (!member) return Result<FederationPlan>::failure(member.error);
    auto parsed_member = MemberId::parse(*member);
    if (!parsed_member) return Result<FederationPlan>::failure(parsed_member.error);
    entry.member = *parsed_member;
    auto site = item.require_string("site");
    if (!site) return Result<FederationPlan>::failure(site.error);
    auto parsed_site = SiteId::parse(*site);
    if (!parsed_site) return Result<FederationPlan>::failure(parsed_site.error);
    entry.site = *parsed_site;
    plan.sites.push_back(entry);
  }
  status = validate_plan(plan);
  if (!status.ok()) return Result<FederationPlan>::failure(status.error);
  return Result<FederationPlan>::success(std::move(plan));
}

Result<FederationPlan> load_plan(const std::filesystem::path& path) {
  auto text = platform::read_file(path, limits::kMaxJsonDocumentBytes);
  if (!text) return Result<FederationPlan>::failure(text.error);
  auto parsed = JsonValue::parse(*text);
  if (!parsed) return Result<FederationPlan>::failure(parsed.error);
  return plan_from_json(*parsed);
}

Status save_plan(const FederationPlan& plan, const std::filesystem::path& path) {
  const Status validity = validate_plan(plan);
  if (!validity.ok()) return validity;
  return platform::write_file_atomic(path, plan_to_json(plan).dump(true) + "\n");
}

Result<FederationPlan> generate_scenario(std::uint64_t seed, std::size_t site_count,
                                         std::size_t bundles_per_publisher) {
  if (site_count == 0 || site_count > 64) {
    return Result<FederationPlan>::failure(ErrorCode::InvalidArgument,
                                           "scenario needs between 1 and 64 sites");
  }
  if (bundles_per_publisher == 0 || bundles_per_publisher > 16) {
    return Result<FederationPlan>::failure(ErrorCode::InvalidArgument,
                                           "scenario needs between 1 and 16 bundles per publisher");
  }
  IdGenerator ids(seed);
  const Timestamp issued_at{platform::system_now_millis()};

  FederationPlan plan;
  plan.federation.value = ids.next();
  plan.root_member.value = ids.next();
  plan.coordinator_site.value = ids.next();
  const MemberId publisher_a{ids.next()};
  const MemberId publisher_b{ids.next()};

  plan.catalog.generation = Generation{2};
  plan.catalog.capabilities.push_back(CapabilityRef{"power.metering", SemanticVersion{2, 1, 0}});
  plan.catalog.capabilities.push_back(CapabilityRef{"cooling.liquid", SemanticVersion{1, 4, 0}});
  plan.catalog.capabilities.push_back(CapabilityRef{"network.rdma", SemanticVersion{1, 0, 0}});

  for (std::size_t i = 0; i < site_count; ++i) {
    PlanSite entry;
    entry.member.value = ids.next();
    entry.site.value = ids.next();
    plan.membership.entries.emplace_back(entry.member, entry.site);
    plan.sites.push_back(entry);
  }

  const AuthorityGrant root =
      make_plan_grant(ids, plan.federation, plan.root_member, publisher_a, GrantId{},
                      AuthorityAction::Delegate, RuleScope::federation(), {});
  plan.grants.push_back(root);
  const std::vector<std::string> domains{"power", "cooling", "network"};
  for (MemberId publisher : {publisher_a, publisher_b}) {
    plan.grants.push_back(make_plan_grant(ids, plan.federation, publisher_a, publisher, root.id,
                                          AuthorityAction::PublishMandatory, RuleScope::federation(),
                                          domains));
    plan.grants.push_back(make_plan_grant(ids, plan.federation, publisher_a, publisher, root.id,
                                          AuthorityAction::PublishPolicy, RuleScope::federation(),
                                          domains));
  }
  for (const PlanSite& entry : plan.sites) {
    plan.grants.push_back(make_plan_grant(ids, plan.federation, publisher_a, entry.member, root.id,
                                          AuthorityAction::OverridePolicy,
                                          RuleScope::for_members({entry.member}), {"power", "cooling"}));
  }

  // Bundle and rule identities come from a stream derived from the scenario parameters, so two
  // different scenarios never emit the same identity with different content.
  IdGenerator bundle_ids(seed * 131ull + static_cast<std::uint64_t>(bundles_per_publisher) * 1013ull +
                         static_cast<std::uint64_t>(site_count) * 7919ull);

  const auto publish_for = [&](MemberId publisher, Generation generation, std::size_t index,
                               bool primary) {
    std::vector<Rule> rules;
    const std::string mandatory_subject = publisher == publisher_a ? "max_kw" : "target_kw";
    Rule mandatory = make_plan_rule(bundle_ids, "power", mandatory_subject,
                                    SettingValue::integer_value(120), RuleClass::Mandatory);
    mandatory.override_permission = primary ? OverridePermission::AllowedWithAuthority
                                            : OverridePermission::Prohibited;
    mandatory.staleness = StalenessPolicy::allow_last_known_valid(2 * 24 * 60 * 60 * 1000);
    mandatory.rationale = "equipment envelope";
    if (primary) {
      mandatory.capability_requirements.push_back(
          CapabilityRequirement{"power.metering", SemanticVersion{2, 1, 0}, false});
    }
    rules.push_back(mandatory);
    rules.push_back(make_plan_rule(bundle_ids, "cooling", "target_c",
                                   SettingValue::integer_value(24), RuleClass::Default));
    rules.push_back(make_plan_rule(bundle_ids, "network", "preferred_path",
                                   SettingValue::text_value("fabric"), RuleClass::Advisory));
    Rule default_with_capability = make_plan_rule(bundle_ids, "cooling", "loop_mode",
                                                  SettingValue::text_value("closed"), RuleClass::Default);
    default_with_capability.capability_requirements.push_back(
        CapabilityRequirement{"cooling.liquid", SemanticVersion{1, 4, 0}, false});
    rules.push_back(default_with_capability);

    // A site-scoped rule exercises scoped applicability without contradicting the shared subject.
    const PlanSite& target = plan.sites[index % plan.sites.size()];
    rules.push_back(make_plan_rule(bundle_ids, "power", "reserve_kw",
                                   SettingValue::integer_value(10), RuleClass::Default,
                                   RuleScope::for_sites({target.site})));
    return seal_plan_bundle(bundle_ids, plan.federation, publisher, generation, RuleScope::federation(),
                            std::move(rules), issued_at, StalenessPolicy::require_fresh(),
                            plan.catalog.generation, "federation-scenario");
  };

  // Override permission varies by generation within a publisher, not by publisher: the first
  // publication of a publisher permits delegated override, and every later one forbids it. That
  // makes "policy moved on and now binds harder" a real, testable transition.
  for (std::size_t i = 0; i < bundles_per_publisher; ++i) {
    plan.bundles.push_back(publish_for(publisher_a, Generation{i + 1}, i, i == 0));
  }
  for (std::size_t i = 0; i < bundles_per_publisher; ++i) {
    plan.bundles.push_back(publish_for(publisher_b, Generation{i + 1}, i + 1, i == 0));
  }

  const Status validity = validate_plan(plan);
  if (!validity.ok()) return Result<FederationPlan>::failure(validity.error);
  return Result<FederationPlan>::success(std::move(plan));
}

Result<LocalOverride> make_override_for_subject(IdGenerator& ids, const FederationPlan& plan,
                                                const PlanSite& site, const EffectivePolicy& policy,
                                                const std::string& domain, const std::string& subject,
                                                SettingValue value, GrantId authority,
                                                const std::string& author, const std::string& reason,
                                                Timestamp now, Generation local_generation) {
  const EffectiveEntry* entry = policy.find(domain, subject);
  if (entry == nullptr) {
    return Result<LocalOverride>::failure(ErrorCode::NotFound, "no policy addresses this subject",
                                          domain + "/" + subject);
  }
  if (entry->source_rule.is_nil() || entry->source_bundle.is_nil()) {
    return Result<LocalOverride>::failure(ErrorCode::InvalidState,
                                          "governing policy has no source this site holds",
                                          domain + "/" + subject);
  }
  LocalOverride record;
  record.id.value = ids.next();
  record.federation = plan.federation;
  record.site = site.site;
  record.member = site.member;
  record.domain = domain;
  record.subject = subject;
  record.target_rule = entry->source_rule;
  record.target_rule_digest = entry->source_rule_digest;
  record.target_bundle = entry->source_bundle;
  record.target_bundle_generation = entry->source_generation;
  record.target_bundle_digest = entry->source_bundle_digest;
  record.local_generation = local_generation;
  record.value = std::move(value);
  record.authority = authority;
  record.author = author;
  record.reason = reason;
  record.created_at = now;
  const Status sealed = seal_override(record);
  if (!sealed.ok()) return Result<LocalOverride>::failure(sealed.error);
  return Result<LocalOverride>::success(std::move(record));
}

}  // namespace gpf
