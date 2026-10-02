#include "fixtures.hpp"
#include "test_support.hpp"

#include <algorithm>
#include <string>

using namespace gpf;
using namespace gpf_test;

GPF_TEST(policy, semantic_versions_parse_and_compare) {
  auto version = SemanticVersion::parse("2.10.3");
  REQUIRE(version.ok());
  CHECK_EQ(version->major, std::uint32_t{2});
  CHECK_EQ(version->minor, std::uint32_t{10});
  CHECK_EQ(version->patch, std::uint32_t{3});
  CHECK_EQ(version->to_string(), std::string("2.10.3"));
  CHECK(!SemanticVersion::parse("1.2").ok());
  CHECK(!SemanticVersion::parse("1.2.3.4").ok());
  CHECK(!SemanticVersion::parse("1.2.x").ok());
  CHECK(!SemanticVersion::parse("1.2.3-rc1").ok());
  CHECK(!SemanticVersion::parse("").ok());
  CHECK(SemanticVersion{1, 2, 0} < SemanticVersion{1, 3, 0});
  CHECK(SemanticVersion{1, 2, 0}.backward_compatible_with(SemanticVersion{1, 2, 9}));
  CHECK(!SemanticVersion{1, 3, 0}.backward_compatible_with(SemanticVersion{1, 2, 9}));
  CHECK(!SemanticVersion{2, 0, 0}.backward_compatible_with(SemanticVersion{1, 9, 9}));
}

GPF_TEST(policy, scope_validation_rejects_implicit_authority) {
  IdGenerator ids(7);
  const MemberId member = make_member(ids);
  const SiteId site = make_site(ids);

  RuleScope federation_scope = RuleScope::federation();
  CHECK(validate_scope(federation_scope).ok());
  federation_scope.members.push_back(member);
  CHECK(!validate_scope(federation_scope).ok());

  const RuleScope empty_member_scope = RuleScope::for_members({});
  CHECK(!validate_scope(empty_member_scope).ok());
  const RuleScope empty_site_scope = RuleScope::for_sites({});
  CHECK(!validate_scope(empty_site_scope).ok());

  RuleScope mixed = RuleScope::for_sites({site});
  mixed.members.push_back(member);
  CHECK(!validate_scope(mixed).ok());

  const RuleScope duplicate = RuleScope::for_sites({site, site});
  CHECK(!validate_scope(duplicate).ok());

  CHECK(scope_contains_site(RuleScope::federation(), member, site));
  CHECK(scope_contains_site(RuleScope::for_sites({site}), member, site));
  CHECK(!scope_contains_site(RuleScope::for_sites({make_site(ids)}), member, site));
  CHECK(scope_contains_site(RuleScope::for_members({member}), member, make_site(ids)));

  CHECK(scope_contains_scope(RuleScope::federation(), RuleScope::for_sites({site})));
  CHECK(!scope_contains_scope(RuleScope::for_sites({site}), RuleScope::federation()));
  CHECK(scope_contains_scope(RuleScope::for_members({member}), RuleScope::for_members({member})));
  CHECK(!scope_contains_scope(RuleScope::for_members({member}), RuleScope::for_sites({site})));
}

GPF_TEST(policy, rule_validation_enforces_declared_contract) {
  IdGenerator ids(11);
  const SiteId site = make_site(ids);

  Rule rule = make_rule(ids, "power", "max_kw", int_value(100));
  CHECK(validate_rule(rule).ok());

  Rule unset = rule;
  unset.value = SettingValue::unset();
  CHECK(!validate_rule(unset).ok());

  Rule broken_identifier = rule;
  broken_identifier.domain = "not a domain";
  CHECK(!validate_rule(broken_identifier).ok());

  Rule nil_identity = rule;
  nil_identity.id = RuleId{};
  CHECK(!validate_rule(nil_identity).ok());

  Rule precedence_on_default = rule;
  precedence_on_default.precedence = 5;
  CHECK(!validate_rule(precedence_on_default).ok());
  Rule precedence_on_mandatory = rule;
  precedence_on_mandatory.rule_class = RuleClass::Mandatory;
  precedence_on_mandatory.precedence = 5;
  precedence_on_mandatory.override_permission = OverridePermission::Prohibited;
  CHECK(validate_rule(precedence_on_mandatory).ok());

  Rule prohibited_default = rule;
  prohibited_default.override_permission = OverridePermission::Prohibited;
  CHECK(!validate_rule(prohibited_default).ok());

  Rule last_known_valid_on_default = rule;
  last_known_valid_on_default.staleness = StalenessPolicy::allow_last_known_valid(kHour);
  CHECK(!validate_rule(last_known_valid_on_default).ok());
  Rule last_known_valid_on_mandatory = rule;
  last_known_valid_on_mandatory.rule_class = RuleClass::Mandatory;
  last_known_valid_on_mandatory.staleness = StalenessPolicy::allow_last_known_valid(kHour);
  CHECK(validate_rule(last_known_valid_on_mandatory).ok());
  Rule absurd_window = last_known_valid_on_mandatory;
  absurd_window.staleness = StalenessPolicy::allow_last_known_valid(0);
  CHECK(!validate_rule(absurd_window).ok());

  Rule inconsistent_times = rule;
  inconsistent_times.effective_from = at(1000);
  inconsistent_times.expires_at = at(1000);
  CHECK(!validate_rule(inconsistent_times).ok());

  Rule too_many_requirements = rule;
  for (std::size_t i = 0; i < limits::kMaxCapabilityRequirementsPerRule + 1; ++i) {
    too_many_requirements.capability_requirements.push_back(
        CapabilityRequirement{"cap" + std::to_string(i), SemanticVersion{1, 0, 0}, false});
  }
  CHECK(!validate_rule(too_many_requirements).ok());

  Rule duplicate_requirement = rule;
  duplicate_requirement.capability_requirements.push_back(
      CapabilityRequirement{"cooling.liquid", SemanticVersion{1, 0, 0}, false});
  duplicate_requirement.capability_requirements.push_back(
      CapabilityRequirement{"cooling.liquid", SemanticVersion{2, 0, 0}, false});
  CHECK(!validate_rule(duplicate_requirement).ok());

  Rule invalid_capability = rule;
  invalid_capability.capability_requirements.push_back(
      CapabilityRequirement{"bad capability", SemanticVersion{1, 0, 0}, false});
  CHECK(!validate_rule(invalid_capability).ok());

  Rule scoped = make_rule(ids, "power", "max_kw", int_value(50), RuleClass::Default,
                          RuleScope::for_sites({site}));
  CHECK(validate_rule(scoped).ok());
  CHECK(scoped.applies_to(make_member(ids), site));
  CHECK(!scoped.applies_to(make_member(ids), make_site(ids)));
}

GPF_TEST(policy, setting_values_are_typed_not_coerced) {
  CHECK(int_value(1) == int_value(1));
  CHECK(!(int_value(1) == text_value("1")));
  CHECK(!(bool_value(true) == int_value(1)));
  CHECK(!(SettingValue::unset() == bool_value(false)));
  CHECK_EQ(int_value(7).to_display_string(), std::string("7"));
  CHECK_EQ(bool_value(true).to_display_string(), std::string("true"));
  CHECK_EQ(text_value("x").to_display_string(), std::string("x"));
  CHECK_EQ(std::string(int_value(1).type_name()), std::string("integer"));
}

GPF_TEST(policy, bundle_validation_and_contradiction_detection) {
  IdGenerator ids(21);
  const FederationId federation = make_federation(ids);
  const MemberId issuer = make_member(ids);
  const SiteId site = make_site(ids);

  std::vector<Rule> rules;
  rules.push_back(make_rule(ids, "power", "max_kw", int_value(100)));
  rules.push_back(make_rule(ids, "power", "min_kw", int_value(10)));
  PolicyBundle bundle = make_bundle(ids, federation, issuer, Generation{1}, rules, at(kDay));
  CHECK(validate_bundle(bundle).ok());
  CHECK(verify_bundle(bundle).ok());

  // Contradictory rules inside one bundle are an authoring defect.
  std::vector<Rule> contradictory;
  contradictory.push_back(make_rule(ids, "power", "max_kw", int_value(100)));
  contradictory.push_back(make_rule(ids, "power", "max_kw", int_value(120)));
  PolicyBundle conflict_bundle =
      make_bundle(ids, federation, issuer, Generation{1}, contradictory, at(kDay));
  auto conflict_status = validate_bundle(conflict_bundle);
  CHECK(!conflict_status.ok());
  CHECK_EQ(error_code_name(conflict_status.error.code), std::string("conflict"));

  // Equal values are not a contradiction.
  std::vector<Rule> duplicate_values;
  duplicate_values.push_back(make_rule(ids, "power", "max_kw", int_value(100)));
  duplicate_values.push_back(make_rule(ids, "power", "max_kw", int_value(100)));
  CHECK(validate_bundle(make_bundle(ids, federation, issuer, Generation{1}, duplicate_values, at(kDay))).ok());

  // Different classes may legitimately share a subject.
  std::vector<Rule> mixed_classes;
  mixed_classes.push_back(make_rule(ids, "power", "max_kw", int_value(100), RuleClass::Mandatory));
  mixed_classes.push_back(make_rule(ids, "power", "max_kw", int_value(80)));
  CHECK(validate_bundle(make_bundle(ids, federation, issuer, Generation{1}, mixed_classes, at(kDay))).ok());

  // Mandatory rules with distinct precedence resolve rather than conflict.
  std::vector<Rule> precedence_rules;
  precedence_rules.push_back(
      make_rule(ids, "power", "max_kw", int_value(100), RuleClass::Mandatory, RuleScope::federation(), 1));
  precedence_rules.push_back(
      make_rule(ids, "power", "max_kw", int_value(90), RuleClass::Mandatory, RuleScope::federation(), 2));
  CHECK(validate_bundle(make_bundle(ids, federation, issuer, Generation{1}, precedence_rules, at(kDay))).ok());

  // A bundle may not carry rules wider than its own scope.
  std::vector<Rule> wider;
  wider.push_back(make_rule(ids, "power", "max_kw", int_value(100)));
  PolicyBundle narrow = make_bundle(ids, federation, issuer, Generation{1}, wider, at(kDay),
                                    RuleScope::for_sites({site}));
  CHECK(!validate_bundle(narrow).ok());

  // Duplicate rule identities are refused.
  Rule shared = make_rule(ids, "power", "max_kw", int_value(100));
  std::vector<Rule> duplicated;
  duplicated.push_back(shared);
  duplicated.push_back(shared);
  auto duplicated_status =
      validate_bundle(make_bundle(ids, federation, issuer, Generation{1}, duplicated, at(kDay)));
  CHECK(!duplicated_status.ok());
  CHECK_EQ(error_code_name(duplicated_status.error.code), std::string("duplicate-identity"));
}

GPF_TEST(policy, bundle_sealing_detects_tampering) {
  IdGenerator ids(31);
  const FederationId federation = make_federation(ids);
  const MemberId issuer = make_member(ids);
  std::vector<Rule> rules;
  rules.push_back(make_rule(ids, "power", "max_kw", int_value(100)));
  rules.push_back(make_rule(ids, "power", "min_kw", int_value(10)));
  PolicyBundle bundle = make_bundle(ids, federation, issuer, Generation{4}, rules, at(kDay));
  CHECK(verify_bundle(bundle).ok());

  PolicyBundle tampered = bundle;
  tampered.rules[0].value = int_value(999);
  auto status = verify_bundle(tampered);
  CHECK(!status.ok());
  CHECK_EQ(error_code_name(status.error.code), std::string("integrity-failure"));

  PolicyBundle tampered_generation = bundle;
  tampered_generation.global_generation = Generation{5};
  CHECK(!verify_bundle(tampered_generation).ok());

  // Canonicalization: the same content in a different order yields the same digest.
  const PolicyBundleId shared_id = make_bundle_id(ids);
  std::vector<Rule> reordered_rules{rules[1], rules[0]};
  PolicyBundle first =
      make_bundle(ids, federation, issuer, Generation{9}, rules, at(kDay),
                  RuleScope::federation(), StalenessPolicy::require_fresh(), SemanticVersion{1, 0, 0},
                  Generation{1}, "canonical", shared_id);
  PolicyBundle second =
      make_bundle(ids, federation, issuer, Generation{9}, reordered_rules, at(kDay),
                  RuleScope::federation(), StalenessPolicy::require_fresh(), SemanticVersion{1, 0, 0},
                  Generation{1}, "canonical", shared_id);
  CHECK(first.integrity_digest == second.integrity_digest);
  CHECK(first.rules[0].id == second.rules[0].id);
  CHECK_EQ(first.rules[0].key(), second.rules[0].key());

  // A capability requirement list is order-insensitive as well.
  Rule with_two = make_rule(ids, "cooling", "mode", text_value("liquid"), RuleClass::Mandatory);
  with_two.capability_requirements.push_back(
      CapabilityRequirement{"cooling.liquid", SemanticVersion{1, 0, 0}, false});
  with_two.capability_requirements.push_back(
      CapabilityRequirement{"cooling.air", SemanticVersion{1, 0, 0}, true});
  Rule reversed = with_two;
  std::reverse(reversed.capability_requirements.begin(), reversed.capability_requirements.end());
  CHECK(*compute_rule_digest(with_two) == *compute_rule_digest(reversed));
}

GPF_TEST(policy, bundle_without_attributable_provenance_is_refused) {
  IdGenerator ids(41);
  const FederationId federation = make_federation(ids);
  const MemberId issuer = make_member(ids);
  std::vector<Rule> rules;
  rules.push_back(make_rule(ids, "power", "max_kw", int_value(100)));
  const PolicyBundle bundle = make_bundle(ids, federation, issuer, Generation{1}, rules, at(kDay));
  PolicyBundle unattributed = bundle;
  unattributed.provenance.clear();
  CHECK(!validate_bundle(unattributed).ok());

  // A broken chain (second entry not chained to the first) is refused.
  PolicyBundle chained = bundle;
  chained.provenance.push_back(make_provenance("second", issuer, GrantId{}, Epoch{1}, Generation{1},
                                               at(kDay), Digest{}, "no chain"));
  auto status = validate_bundle(chained);
  CHECK(!status.ok());
  CHECK_EQ(error_code_name(status.error.code), std::string("integrity-failure"));

  // A correctly chained second entry is accepted.
  PolicyBundle properly_chained = bundle;
  properly_chained.provenance.push_back(
      make_provenance("second", issuer, GrantId{}, Epoch{1}, Generation{1}, at(kDay),
                      properly_chained.provenance.back().entry_digest, "amendment"));
  CHECK(validate_bundle(properly_chained).ok());
}

GPF_TEST(policy, bundle_and_override_json_round_trip) {
  IdGenerator ids(51);
  const FederationId federation = make_federation(ids);
  const MemberId issuer = make_member(ids);
  const SiteId site = make_site(ids);
  Rule mandatory = make_rule(ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  mandatory.override_permission = OverridePermission::AllowedWithAuthority;
  mandatory.staleness = StalenessPolicy::allow_last_known_valid(kHour);
  mandatory.capability_requirements.push_back(
      CapabilityRequirement{"power.metering", SemanticVersion{2, 1, 0}, false});
  mandatory.rationale = "keep inlet temperatures inside the equipment envelope";
  std::vector<Rule> rules{mandatory};
  PolicyBundle bundle = make_bundle(ids, federation, issuer, Generation{3}, rules, at(kDay));
  bundle.expires_at = at(30 * kDay);
  // Mutating authoritative content invalidates the seal; re-sealing is what a publisher does.
  REQUIRE(seal_bundle(bundle).ok());
  REQUIRE(verify_bundle(bundle).ok());

  const std::string dumped = bundle_to_json(bundle).dump();
  auto parsed = JsonValue::parse(dumped);
  REQUIRE(parsed.ok());
  auto restored = bundle_from_json(*parsed);
  if (!restored.ok()) NOTE("bundle_from_json failed: " + restored.error.to_string());
  REQUIRE(restored.ok());
  CHECK(restored->integrity_digest == bundle.integrity_digest);
  CHECK_EQ(restored->rules.size(), std::size_t{1});
  CHECK(restored->rules[0].capability_requirements.size() == 1);
  CHECK(restored->rules[0].staleness.mode == StalenessPolicy::Mode::AllowLastKnownValid);
  CHECK_EQ(restored->rules[0].rationale, mandatory.rationale);

  // Tampering with the value after serialization is detected.
  auto tampered_json = JsonValue::parse(dumped);
  REQUIRE(tampered_json.ok());
  auto rules_array = tampered_json->find("rules");
  REQUIRE(rules_array != nullptr);
  JsonValue::Array items = rules_array->array_items();
  items[0].set_field("value", setting_value_to_json(int_value(1)));
  tampered_json->set_field("rules", JsonValue::array(std::move(items)));
  auto tampered = bundle_from_json(*tampered_json);
  CHECK(!tampered.ok());

  const LocalOverride override_record =
      make_override(ids, federation, issuer, site, mandatory, bundle, Generation{1}, int_value(90),
                    "site-reliability", "local thermal envelope is tighter", GrantId{}, at(kDay));
  const std::string override_json = override_to_json(override_record).dump();
  auto parsed_override = JsonValue::parse(override_json);
  REQUIRE(parsed_override.ok());
  auto restored_override = override_from_json(*parsed_override);
  REQUIRE(restored_override.ok());
  CHECK(restored_override->digest == override_record.digest);
  CHECK(!validate_override(LocalOverride{}).ok());

  LocalOverride without_reason = override_record;
  without_reason.reason.clear();
  CHECK(!validate_override(without_reason).ok());
  LocalOverride without_generation = override_record;
  without_generation.target_bundle_generation = Generation{};
  CHECK(!validate_override(without_generation).ok());
  LocalOverride without_author = override_record;
  without_author.author.clear();
  CHECK(!validate_override(without_author).ok());
}

GPF_TEST(policy, capability_negotiation_keeps_unknown_distinct) {
  const CapabilityCatalog catalog = make_catalog(Generation{3}, {{"power.metering", SemanticVersion{2, 1, 0}},
                                                                {"cooling.liquid", SemanticVersion{1, 4, 0}}});
  CHECK(validate_capability_catalog(catalog).ok());
  CHECK_EQ(catalog.find("power.metering")->version.to_string(), std::string("2.1.0"));
  CHECK(catalog.find("nothing") == nullptr);

  const SiteCapabilitySnapshot current =
      make_snapshot(Generation{3}, {{"power.metering", SemanticVersion{2, 2, 0}}});
  const SiteCapabilitySnapshot stale =
      make_snapshot(Generation{2}, {{"power.metering", SemanticVersion{2, 2, 0}}});
  const SiteCapabilitySnapshot stale_without_declaration = make_snapshot(Generation{2}, {});
  const SiteCapabilitySnapshot empty_current = make_snapshot(Generation{3}, {});
  const SiteCapabilitySnapshot old_version =
      make_snapshot(Generation{3}, {{"power.metering", SemanticVersion{2, 0, 0}}});

  const CapabilityRequirement requirement{"power.metering", SemanticVersion{2, 1, 0}, false};
  CHECK(negotiate_capability(requirement, current, catalog) == NegotiationOutcome::Satisfied);
  CHECK(negotiate_capability(requirement, empty_current, catalog) ==
        NegotiationOutcome::UnsupportedCapability);
  CHECK(negotiate_capability(requirement, old_version, catalog) == NegotiationOutcome::VersionMismatch);
  CHECK(negotiate_capability(requirement, stale_without_declaration, catalog) ==
        NegotiationOutcome::CatalogStale);
  const CapabilityRequirement unknown{"fusion.reactor", SemanticVersion{1, 0, 0}, false};
  CHECK(negotiate_capability(unknown, current, catalog) == NegotiationOutcome::UnknownCapability);

  // A site that declares the capability at a sufficient version is satisfied even when its
  // catalog view lags: only absence claims are affected by staleness.
  const SiteCapabilitySnapshot stale_with_declaration =
      make_snapshot(Generation{1}, {{"power.metering", SemanticVersion{2, 1, 0}}});
  CHECK(negotiate_capability(requirement, stale_with_declaration, catalog) ==
        NegotiationOutcome::Satisfied);

  CHECK(!validate_capability_catalog(make_catalog(Generation{1}, {{"a.b", SemanticVersion{1, 0, 0}},
                                                                {"a.b", SemanticVersion{2, 0, 0}}})).ok());
  CHECK(!validate_capability_catalog(make_catalog(Generation{1}, {{"bad name", SemanticVersion{1, 0, 0}}})).ok());
  CHECK(validate_capability_snapshot(SiteCapabilitySnapshot{}).ok());
}