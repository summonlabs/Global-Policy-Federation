#include "fixtures.hpp"
#include "test_support.hpp"

#include <algorithm>
#include <string>

using namespace gpf;
using namespace gpf_test;

namespace {

const Receipt* find_receipt(const EffectivePolicy& policy, ReceiptKind kind,
                            const std::string& reason_code) {
  for (const Receipt& receipt : policy.receipts) {
    if (receipt.kind == kind && receipt.reason_code == reason_code) return &receipt;
  }
  return nullptr;
}

std::size_t count_receipts(const EffectivePolicy& policy, ReceiptKind kind) {
  std::size_t total = 0;
  for (const Receipt& receipt : policy.receipts) {
    if (receipt.kind == kind) ++total;
  }
  return total;
}

bool explanation_mentions(const EffectiveEntry& entry, const std::string& needle) {
  for (const std::string& line : entry.explanation) {
    if (line.find(needle) != std::string::npos) return true;
  }
  return false;
}

}  // namespace

GPF_TEST(effective, single_default_rule_becomes_active) {
  SiteFixture fixture;
  Rule rule = make_rule(fixture.ids, "power", "max_kw", int_value(100));
  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));

  auto compiled = compile_effective_policy(input);
  if (!compiled.ok()) NOTE("compile failed: " + compiled.error.to_string());
  REQUIRE(compiled.ok());
  const EffectivePolicy& policy = *compiled;
  CHECK_EQ(policy.entries.size(), std::size_t{1});
  CHECK_EQ(policy.rules_considered, std::size_t{1});
  CHECK_EQ(policy.rules_applied, std::size_t{1});
  CHECK_EQ(policy.global_generation.value, std::uint64_t{1});

  const EffectiveEntry& entry = policy.entries[0];
  CHECK(entry.state == EntryState::Active);
  CHECK(entry.value == int_value(100));
  CHECK(entry.effective_class == RuleClass::Default);
  CHECK_EQ(entry.source_rule.to_string(), rule.id.to_string());
  CHECK(entry_state_is_binding(entry.state));
  CHECK(entry.explanation.size() >= 3);
  CHECK(!policy.partitioned);

  const Receipt* applied = find_receipt(policy, ReceiptKind::Applied, "default-policy-applied");
  REQUIRE(applied != nullptr);
  CHECK_EQ(applied->rule.to_string(), rule.id.to_string());
  CHECK(applied->sequence.value >= 1);
  CHECK(validate_effective_policy(policy).ok());

  // Deterministic: the same inputs compile to the same digest, including receipt identities.
  auto again = compile_effective_policy(input);
  REQUIRE(again.ok());
  CHECK(again->digest == policy.digest);
  CHECK_EQ(again->receipts.size(), policy.receipts.size());
}

GPF_TEST(effective, class_and_precedence_decide_and_ties_conflict) {
  SiteFixture fixture;
  Rule default_rule = make_rule(fixture.ids, "power", "max_kw", int_value(80));
  Rule mandatory = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory,
                             RuleScope::federation(), 1);
  Rule mandatory_stronger = make_rule(fixture.ids, "power", "max_kw", int_value(110),
                                      RuleClass::Mandatory, RuleScope::federation(), 5);
  Rule advisory = make_rule(fixture.ids, "power", "max_kw", int_value(70), RuleClass::Advisory);
  Rule other_subject = make_rule(fixture.ids, "power", "min_kw", int_value(5), RuleClass::Mandatory);

  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(
      fixture.global_bundle({default_rule, mandatory, mandatory_stronger, advisory, other_subject},
                            Generation{1}));
  auto compiled = compile_effective_policy(input);
  if (!compiled.ok()) NOTE("compile failed: " + compiled.error.to_string());
  REQUIRE(compiled.ok());

  const EffectiveEntry& entry = *compiled->find("power", "max_kw");
  CHECK(entry.state == EntryState::Active);
  CHECK(entry.value == int_value(110));
  CHECK(entry.effective_class == RuleClass::Mandatory);
  CHECK_EQ(entry.source_rule.to_string(), mandatory_stronger.id.to_string());
  CHECK_EQ(compiled->conflicts.size(), std::size_t{0});
  CHECK(compiled->find("power", "min_kw") != nullptr);

  // Equal precedence with differing values is an authoritative conflict, contained to the
  // subject. The neighbouring subject still compiles.
  SiteFixture second;
  Rule left = make_rule(second.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  Rule right = make_rule(second.ids, "power", "max_kw", int_value(120), RuleClass::Mandatory);
  Rule untouched = make_rule(second.ids, "power", "min_kw", int_value(5), RuleClass::Mandatory);
  // Contradiction across two independently valid publications from different publishers: the
  // compiler must contain it rather than pick a winner.
  EffectivePolicyInput conflict_input = second.input();
  conflict_input.accepted_bundles.push_back(second.global_bundle({left, untouched}, Generation{1}));
  conflict_input.accepted_bundles.push_back(
      second.global_bundle({right}, Generation{1}, StalenessPolicy::require_fresh(), Timestamp{0},
                           SemanticVersion{1, 0, 0}, Generation{1}, RuleScope::federation(),
                           second.second_operator_member));
  auto conflicted = compile_effective_policy(conflict_input);
  REQUIRE(conflicted.ok());
  CHECK_EQ(conflicted->entries.size(), std::size_t{2});
  REQUIRE(conflicted->conflicts.size() == 1);
  const EffectiveEntry& conflicted_entry = *conflicted->find("power", "max_kw");
  CHECK(conflicted_entry.state == EntryState::Conflicted);
  CHECK(!entry_state_is_binding(conflicted_entry.state));
  CHECK(!conflicted_entry.conflict.is_nil());
  CHECK_EQ(conflicted_entry.reason_code, std::string(reasons::kContradictoryMandatory));
  CHECK_EQ(conflicted->conflicts.size(), std::size_t{1});
  CHECK(conflicted->conflicts[0].contained);
  CHECK_EQ(conflicted->conflicts[0].participants.size(), std::size_t{2});
  CHECK(conflicted->find("power", "min_kw")->state == EntryState::Active);
  CHECK(find_receipt(*conflicted, ReceiptKind::ConflictRecorded,
                     reasons::kContradictoryMandatory) != nullptr);
}

GPF_TEST(effective, local_default_supersedes_federated_default) {
  SiteFixture fixture;
  Rule federated = make_rule(fixture.ids, "power", "max_kw", int_value(100));
  Rule local = make_rule(fixture.ids, "power", "max_kw", int_value(90), RuleClass::Default,
                         RuleScope::for_sites({fixture.site}));

  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(fixture.global_bundle({federated}, Generation{1}));
  input.local_bundles.push_back(fixture.local_bundle({local}, Generation{1}));
  auto compiled = compile_effective_policy(input);
  REQUIRE(compiled.ok());
  const EffectiveEntry& entry = *compiled->find("power", "max_kw");
  CHECK(entry.state == EntryState::Active);
  CHECK(entry.value == int_value(90));
  CHECK_EQ(entry.source_rule.to_string(), local.id.to_string());
  CHECK_EQ(entry.reason_code, std::string("default-policy-applied"));
  CHECK_EQ(compiled->local_generation.value, std::uint64_t{1});

  // Two federated defaults that disagree are a conflict: local sovereignty is not a licence for
  // federated sources to contradict each other silently.
  SiteFixture second;
  Rule left = make_rule(second.ids, "power", "max_kw", int_value(100));
  Rule right = make_rule(second.ids, "power", "max_kw", int_value(120));
  EffectivePolicyInput conflicting = second.input();
  conflicting.accepted_bundles.push_back(second.global_bundle({left}, Generation{1}));
  conflicting.accepted_bundles.push_back(
      second.global_bundle({right}, Generation{1}, StalenessPolicy::require_fresh(), Timestamp{0},
                           SemanticVersion{1, 0, 0}, Generation{1}, RuleScope::federation(),
                           second.second_operator_member));
  auto compiled_conflict = compile_effective_policy(conflicting);
  REQUIRE(compiled_conflict.ok());
  CHECK(compiled_conflict->find("power", "max_kw")->state == EntryState::Conflicted);

  // Local alone is authoritative for its own site.
  SiteFixture third;
  Rule local_only = make_rule(third.ids, "power", "max_kw", int_value(75), RuleClass::Default,
                              RuleScope::for_sites({third.site}));
  EffectivePolicyInput local_input = third.input();
  local_input.local_bundles.push_back(third.local_bundle({local_only}, Generation{1}));
  auto compiled_local = compile_effective_policy(local_input);
  REQUIRE(compiled_local.ok());
  CHECK(compiled_local->find("power", "max_kw")->state == EntryState::Active);
  CHECK_EQ(compiled_local->global_generation.value, std::uint64_t{0});
}

GPF_TEST(effective, advisory_never_binds) {
  SiteFixture fixture;
  Rule advisory = make_rule(fixture.ids, "cooling", "preferred_mode", text_value("liquid"),
                            RuleClass::Advisory);
  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(fixture.global_bundle({advisory}, Generation{1}));
  auto compiled = compile_effective_policy(input);
  REQUIRE(compiled.ok());
  const EffectiveEntry& entry = *compiled->find("cooling", "preferred_mode");
  CHECK(entry.state == EntryState::Advisory);
  CHECK(!entry_state_is_binding(entry.state));
  CHECK_EQ(entry.reason_code, std::string(reasons::kAdvisoryOnly));
  CHECK(explanation_mentions(entry, "informational"));
  CHECK_EQ(count_receipts(*compiled, ReceiptKind::Applied), std::size_t{0});

  // Disagreeing advisory rules are recorded but never become an authoritative conflict.
  SiteFixture second;
  Rule left = make_rule(second.ids, "cooling", "preferred_mode", text_value("liquid"),
                        RuleClass::Advisory);
  Rule right = make_rule(second.ids, "cooling", "preferred_mode", text_value("air"),
                         RuleClass::Advisory);
  EffectivePolicyInput advisory_input = second.input();
  advisory_input.accepted_bundles.push_back(second.global_bundle({left}, Generation{1}));
  advisory_input.accepted_bundles.push_back(
      second.global_bundle({right}, Generation{1}, StalenessPolicy::require_fresh(), Timestamp{0},
                           SemanticVersion{1, 0, 0}, Generation{1}, RuleScope::federation(),
                           second.second_operator_member));
  auto compiled_advisory = compile_effective_policy(advisory_input);
  REQUIRE(compiled_advisory.ok());
  const EffectiveEntry& entry_second = *compiled_advisory->find("cooling", "preferred_mode");
  CHECK(entry_second.state == EntryState::Advisory);
  CHECK(!entry_state_is_binding(entry_second.state));
  CHECK(!entry_second.conflict.is_nil());
  CHECK_EQ(compiled_advisory->conflicts.size(), std::size_t{1});
  CHECK(compiled_advisory->conflicts[0].rule_class == RuleClass::Advisory);
}

GPF_TEST(effective, capability_outcomes_stay_distinct) {
  const CapabilityRequirement unsupported_requirement{"cooling.liquid", SemanticVersion{1, 0, 0},
                                                      false};
  const CapabilityRequirement unknown_requirement{"fusion.reactor", SemanticVersion{1, 0, 0}, false};

  // Unsupported capability: refused, not deferred.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"), RuleClass::Mandatory);
    rule.capability_requirements.push_back(unsupported_requirement);
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{1}, {{"cooling.liquid", SemanticVersion{1, 0, 0}}});
    input.capabilities = fixture.snapshot(Generation{1}, {});
    input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("cooling", "mode");
    CHECK(entry.state == EntryState::Incompatible);
    CHECK(!entry_state_is_binding(entry.state));
    CHECK_EQ(compiled->rules_rejected, std::size_t{1});
    CHECK(find_receipt(*compiled, ReceiptKind::Rejected, reasons::kCapabilityUnsatisfied) != nullptr);
  }

  // Unknown capability: deferred, not refused and not silently satisfied.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"), RuleClass::Mandatory);
    rule.capability_requirements.push_back(unknown_requirement);
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{1}, {{"cooling.liquid", SemanticVersion{1, 0, 0}}});
    input.capabilities = fixture.snapshot(Generation{1}, {{"cooling.liquid", SemanticVersion{1, 0, 0}}});
    input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("cooling", "mode");
    CHECK(entry.state == EntryState::Indeterminate);
    CHECK_EQ(entry.reason_code, std::string(reasons::kCapabilityUnknown));
    CHECK_EQ(compiled->rules_deferred, std::size_t{1});
    CHECK(find_receipt(*compiled, ReceiptKind::Deferred, reasons::kCapabilityUnknown) != nullptr);
  }

  // Version mismatch: incompatible, distinguished from unsupported by the detail.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"), RuleClass::Mandatory);
    rule.capability_requirements.push_back(
        CapabilityRequirement{"cooling.liquid", SemanticVersion{2, 0, 0}, false});
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{1}, {{"cooling.liquid", SemanticVersion{2, 0, 0}}});
    input.capabilities = fixture.snapshot(Generation{1}, {{"cooling.liquid", SemanticVersion{1, 5, 0}}});
    input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("cooling", "mode");
    CHECK(entry.state == EntryState::Incompatible);
    CHECK(entry.capability_outcome == NegotiationOutcome::VersionMismatch);
    CHECK(entry.detail.find("version-mismatch") != std::string::npos);
  }

  // Stale capability catalog: deferred, never refused.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"), RuleClass::Mandatory);
    rule.capability_requirements.push_back(unsupported_requirement);
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{3}, {{"cooling.liquid", SemanticVersion{1, 0, 0}}});
    input.capabilities = fixture.snapshot(Generation{1}, {});
    input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    CHECK(compiled->find("cooling", "mode")->state == EntryState::Indeterminate);
    CHECK_EQ(compiled->find("cooling", "mode")->reason_code, std::string(reasons::kCatalogStale));
  }

  // Optional prerequisites are recorded but do not block.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"), RuleClass::Mandatory);
    rule.capability_requirements.push_back(
        CapabilityRequirement{"cooling.liquid", SemanticVersion{9, 0, 0}, true});
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{1}, {{"cooling.liquid", SemanticVersion{9, 0, 0}}});
    input.capabilities = fixture.snapshot(Generation{1}, {});
    input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    CHECK(compiled->find("cooling", "mode")->state == EntryState::Active);
    CHECK_EQ(compiled->rules_rejected, std::size_t{0});
  }

  // A bundle authored against a capability catalog this site has not seen is deferred whole.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"));
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{1}, {});
    input.capabilities = fixture.snapshot(Generation{1}, {});
    input.accepted_bundles.push_back(
        fixture.global_bundle({rule}, Generation{1}, StalenessPolicy::require_fresh(), Timestamp{0},
                              SemanticVersion{1, 0, 0}, Generation{4}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    CHECK(compiled->find("cooling", "mode")->state == EntryState::Indeterminate);
  }

  // A bundle that requires a newer runtime is refused rather than partially applied.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"));
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{1}, {});
    input.capabilities = fixture.snapshot(Generation{1}, {});
    input.accepted_bundles.push_back(
        fixture.global_bundle({rule}, Generation{1}, StalenessPolicy::require_fresh(), Timestamp{0},
                              SemanticVersion{2, 0, 0}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("cooling", "mode");
    CHECK(entry.state == EntryState::Incompatible);
    CHECK_EQ(entry.reason_code, std::string(reasons::kRuntimeIncompatible));
  }
}
GPF_TEST(effective, newer_generation_from_one_publisher_supersedes_the_older) {
  SiteFixture fixture;
  Rule older = make_rule(fixture.ids, "power", "max_kw", int_value(100));
  Rule newer = make_rule(fixture.ids, "power", "max_kw", int_value(120));
  Rule dropped = make_rule(fixture.ids, "power", "legacy_kw", int_value(5));

  PolicyBundle first = fixture.global_bundle({older, dropped}, Generation{1});
  PolicyBundle second = fixture.global_bundle({newer}, Generation{2});

  EffectivePolicyInput input = fixture.input();
  // Deliberately supplied oldest-last: generation order, not arrival order, decides.
  input.accepted_bundles.push_back(second);
  input.accepted_bundles.push_back(first);
  auto compiled = compile_effective_policy(input);
  if (!compiled.ok()) NOTE("compile failed: " + compiled.error.to_string());
  REQUIRE(compiled.ok());

  const EffectiveEntry& entry = *compiled->find("power", "max_kw");
  CHECK(entry.state == EntryState::Active);
  CHECK(entry.value == int_value(120));
  CHECK_EQ(entry.source_generation.value, std::uint64_t{2});
  CHECK_EQ(compiled->rules_superseded, std::size_t{2});
  CHECK(find_receipt(*compiled, ReceiptKind::Superseded, reasons::kGenerationSuperseded) != nullptr);
  // A subject only the superseded generation addressed is no longer addressed at all.
  CHECK(compiled->find("power", "legacy_kw") == nullptr);
  CHECK(explain_subject(*compiled, "power", "legacy_kw").state == EntryState::Absent);

  // Different publishers of the same generation are not superseded: they must agree or conflict.
  SiteFixture independent;
  Rule left = make_rule(independent.ids, "power", "max_kw", int_value(100));
  Rule right = make_rule(independent.ids, "power", "max_kw", int_value(120));
  EffectivePolicyInput cross = independent.input();
  cross.accepted_bundles.push_back(independent.global_bundle({left}, Generation{1}));
  cross.accepted_bundles.push_back(
      independent.global_bundle({right}, Generation{1}, StalenessPolicy::require_fresh(), Timestamp{0},
                                SemanticVersion{1, 0, 0}, Generation{1}, RuleScope::federation(),
                                independent.second_operator_member));
  auto compiled_cross = compile_effective_policy(cross);
  REQUIRE(compiled_cross.ok());
  CHECK(compiled_cross->find("power", "max_kw")->state == EntryState::Conflicted);
  CHECK_EQ(compiled_cross->rules_superseded, std::size_t{0});
}

GPF_TEST(effective, time_expiry_and_revocation_are_distinct_states) {
  // Expiry withholds; it is not absence.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "power", "max_kw", int_value(100));
    rule.effective_from = at(0);
    rule.expires_at = at(50 * kDay);
    EffectivePolicyInput input = fixture.input();
    input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("power", "max_kw");
    CHECK(entry.state == EntryState::Withheld);
    CHECK(!entry_state_is_binding(entry.state));
    CHECK_EQ(entry.reason_code, std::string(reasons::kPolicyExpired));
    CHECK_EQ(compiled->rules_withheld, std::size_t{1});
    CHECK(find_receipt(*compiled, ReceiptKind::Withheld, reasons::kPolicyExpired) != nullptr);
  }

  // Not-yet-effective is a different withholding reason than expiry.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "power", "max_kw", int_value(100));
    rule.effective_from = at(200 * kDay);
    EffectivePolicyInput input = fixture.input();
    input.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{1}));
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    CHECK_EQ(compiled->find("power", "max_kw")->reason_code, std::string(reasons::kPolicyNotYetEffective));
  }

  // Revocation is reported as revocation, never as staleness or absence.
  {
    SiteFixture fixture;
    Rule rule = make_rule(fixture.ids, "power", "max_kw", int_value(100));
    PolicyBundle bundle = fixture.global_bundle({rule}, Generation{1});

    AuthorityLedger ledger(fixture.federation);
    ledger.set_root_member(fixture.operator_member);
    const AuthorityGrant root =
        make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.member, GrantId{},
                   AuthorityAction::Delegate, RuleScope::for_members({fixture.member}));
    REQUIRE(ledger.add_root_grant(root, fixture.now).ok());
    const RevocationRecord rule_revocation =
        make_revocation(fixture.ids, fixture.federation, RevocationTarget::Rule, rule.id.value,
                        fixture.operator_member, "federation-operator", GrantId{}, 1, fixture.now,
                        "rule found unsafe");
    REQUIRE(ledger.add_revocation(rule_revocation, fixture.now).ok());

    EffectivePolicyInput input = fixture.input();
    input.authority = &ledger;
    input.membership = &fixture.membership;
    input.accepted_bundles.push_back(bundle);
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("power", "max_kw");
    CHECK(entry.state == EntryState::Revoked);
    CHECK_EQ(entry.reason_code, std::string(reasons::kRuleRevoked));
    CHECK_EQ(compiled->rules_revoked, std::size_t{1});
    CHECK(find_receipt(*compiled, ReceiptKind::Revoked, reasons::kRuleRevoked) != nullptr);
  }

  // Revoking the publishing bundle revokes every rule it carried.
  {
    SiteFixture fixture;
    Rule first = make_rule(fixture.ids, "power", "max_kw", int_value(100));
    Rule second = make_rule(fixture.ids, "power", "min_kw", int_value(10));
    PolicyBundle bundle = fixture.global_bundle({first, second}, Generation{1});

    AuthorityLedger ledger(fixture.federation);
    ledger.set_root_member(fixture.operator_member);
    const AuthorityGrant root =
        make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.member, GrantId{},
                   AuthorityAction::Delegate, RuleScope::for_members({fixture.member}));
    REQUIRE(ledger.add_root_grant(root, fixture.now).ok());
    const RevocationRecord bundle_revocation =
        make_revocation(fixture.ids, fixture.federation, RevocationTarget::Bundle, bundle.id.value,
                        fixture.operator_member, "federation-operator", GrantId{}, 1, fixture.now,
                        "publication withdrawn");
    REQUIRE(ledger.add_revocation(bundle_revocation, fixture.now).ok());

    EffectivePolicyInput input = fixture.input();
    input.authority = &ledger;
    input.membership = &fixture.membership;
    input.accepted_bundles.push_back(bundle);
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    CHECK(compiled->find("power", "max_kw")->state == EntryState::Revoked);
    CHECK(compiled->find("power", "min_kw")->state == EntryState::Revoked);
    CHECK_EQ(compiled->find("power", "max_kw")->reason_code, std::string(reasons::kPolicyRevoked));
  }
}

GPF_TEST(effective, partition_behavior_is_declared_not_assumed) {
  SiteFixture fixture;
  fixture.now = at(100 * kDay);
  Rule fresh = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  Rule tolerant = make_rule(fixture.ids, "power", "min_kw", int_value(10), RuleClass::Mandatory);
  tolerant.staleness = StalenessPolicy::allow_last_known_valid(2 * kDay);
  Rule short_window = make_rule(fixture.ids, "power", "target_kw", int_value(50), RuleClass::Mandatory);
  short_window.staleness = StalenessPolicy::allow_last_known_valid(kHour / 2);

  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(fixture.global_bundle({fresh, tolerant, short_window}, Generation{7}));
  input.partitioned = true;
  input.last_contact_at = at(100 * kDay - kHour);

  auto compiled = compile_effective_policy(input);
  if (!compiled.ok()) NOTE("compile failed: " + compiled.error.to_string());
  REQUIRE(compiled.ok());
  CHECK(compiled->partitioned);
  // No new global authority is fabricated while disconnected.
  CHECK_EQ(compiled->global_generation.value, std::uint64_t{7});

  const EffectiveEntry& withheld = *compiled->find("power", "max_kw");
  CHECK(withheld.state == EntryState::Withheld);
  CHECK_EQ(withheld.reason_code, std::string(reasons::kPolicyWithheldStale));

  const EffectiveEntry& last_known = *compiled->find("power", "min_kw");
  CHECK(last_known.state == EntryState::LastKnownValid);
  CHECK(entry_state_is_binding(last_known.state));
  CHECK(last_known.value == int_value(10));
  CHECK(explanation_mentions(last_known, "last-known-valid"));
  CHECK(find_receipt(*compiled, ReceiptKind::Applied, reasons::kPolicyLastKnownValid) != nullptr);

  // The declared window is a bound, not a suggestion.
  CHECK(compiled->find("power", "target_kw")->state == EntryState::Withheld);

  // Local policy never goes stale.
  SiteFixture local_fixture;
  Rule local = make_rule(local_fixture.ids, "power", "max_kw", int_value(90), RuleClass::Default,
                         RuleScope::for_sites({local_fixture.site}));
  EffectivePolicyInput local_input = local_fixture.input();
  local_input.local_bundles.push_back(local_fixture.local_bundle({local}, Generation{1}));
  local_input.partitioned = true;
  local_input.last_contact_at = at(0);
  auto compiled_local = compile_effective_policy(local_input);
  REQUIRE(compiled_local.ok());
  CHECK(compiled_local->find("power", "max_kw")->state == EntryState::Active);

  // Reconnection restores currency without changing generations by itself.
  input.partitioned = false;
  auto reconnected = compile_effective_policy(input);
  REQUIRE(reconnected.ok());
  CHECK(reconnected->find("power", "max_kw")->state == EntryState::Active);
  CHECK_EQ(reconnected->global_generation.value, std::uint64_t{7});
}

GPF_TEST(effective, a_prohibition_survives_agreement_between_publishers) {
  // Two publishers state the same mandatory value for one subject. One permits override, the other
  // forbids it. The prohibition governs: agreement on a value must not erase a restriction.
  SiteFixture fixture;
  Rule permissive = make_rule(fixture.ids, "power", "max_kw", int_value(120), RuleClass::Mandatory);
  permissive.override_permission = OverridePermission::Allowed;
  Rule prohibitive = make_rule(fixture.ids, "power", "max_kw", int_value(120), RuleClass::Mandatory);
  prohibitive.override_permission = OverridePermission::Prohibited;

  PolicyBundle first = fixture.global_bundle({permissive}, Generation{1});
  PolicyBundle second =
      fixture.global_bundle({prohibitive}, Generation{1}, StalenessPolicy::require_fresh(),
                            Timestamp{0}, SemanticVersion{1, 0, 0}, Generation{1},
                            RuleScope::federation(), fixture.second_operator_member);

  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(first);
  input.accepted_bundles.push_back(second);
  auto baseline = compile_effective_policy(input);
  if (!baseline.ok()) NOTE("compile failed: " + baseline.error.to_string());
  REQUIRE(baseline.ok());
  const EffectiveEntry& entry = *baseline->find("power", "max_kw");
  CHECK(entry.state == EntryState::Active);
  CHECK(entry.value == int_value(120));
  CHECK_EQ(baseline->conflicts.size(), std::size_t{0});

  const LocalOverride override_record =
      make_override(fixture.ids, fixture.federation, fixture.member, fixture.site, permissive, first,
                    Generation{1}, int_value(95), "site-reliability", "tighter local envelope",
                    GrantId{}, fixture.now);
  EffectivePolicyInput with_override = input;
  with_override.overrides.push_back(override_record);
  auto compiled = compile_effective_policy(with_override);
  REQUIRE(compiled.ok());
  const EffectiveEntry& refused = *compiled->find("power", "max_kw");
  CHECK(refused.state == EntryState::Active);
  CHECK(refused.value == int_value(120));
  CHECK_EQ(compiled->overrides_applied, std::size_t{0});
  CHECK_EQ(compiled->overrides_refused, std::size_t{1});
  CHECK(find_receipt(*compiled, ReceiptKind::Rejected, reasons::kOverrideProhibited) != nullptr);
}

GPF_TEST(effective, overrides_require_authority_generation_and_attribution) {
  // Permitted override: explicit, generation-bound, attributable and visible in the explanation.
  {
    SiteFixture fixture;
    Rule mandatory = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
    mandatory.override_permission = OverridePermission::Allowed;
    PolicyBundle bundle = fixture.global_bundle({mandatory}, Generation{1});
    const LocalOverride override_record =
        make_override(fixture.ids, fixture.federation, fixture.member, fixture.site, bundle.rules[0],
                      bundle, Generation{4}, int_value(90), "site-reliability",
                      "local thermal envelope is tighter", GrantId{}, fixture.now);

    EffectivePolicyInput input = fixture.input();
    input.accepted_bundles.push_back(bundle);
    input.overrides.push_back(override_record);
    auto compiled = compile_effective_policy(input);
    if (!compiled.ok()) NOTE("compile failed: " + compiled.error.to_string());
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("power", "max_kw");
    CHECK(entry.state == EntryState::Overridden);
    CHECK(entry_state_is_binding(entry.state));
    CHECK(entry.value == int_value(90));
    CHECK_EQ(entry.applied_override.to_string(), override_record.id.to_string());
    CHECK_EQ(entry.override_author, std::string("site-reliability"));
    CHECK_EQ(entry.override_local_generation.value, std::uint64_t{4});
    CHECK(explanation_mentions(entry, "site-reliability"));
    CHECK(explanation_mentions(entry, "local thermal envelope is tighter"));
    CHECK_EQ(compiled->overrides_applied, std::size_t{1});
    CHECK_EQ(compiled->local_generation.value, std::uint64_t{4});
    CHECK(find_receipt(*compiled, ReceiptKind::Overridden, "local-override-applied") != nullptr);
  }

  // Prohibited override: deterministic refusal, and the mandatory value stands.
  {
    SiteFixture fixture;
    Rule mandatory = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
    mandatory.override_permission = OverridePermission::Prohibited;
    PolicyBundle bundle = fixture.global_bundle({mandatory}, Generation{1});
    const LocalOverride override_record =
        make_override(fixture.ids, fixture.federation, fixture.member, fixture.site, bundle.rules[0],
                      bundle, Generation{1}, int_value(90), "site-reliability", "we would prefer less",
                      GrantId{}, fixture.now);

    EffectivePolicyInput input = fixture.input();
    input.accepted_bundles.push_back(bundle);
    input.overrides.push_back(override_record);
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("power", "max_kw");
    CHECK(entry.state == EntryState::Active);
    CHECK(entry.value == int_value(100));
    CHECK(entry.applied_override.is_nil());
    CHECK_EQ(compiled->overrides_refused, std::size_t{1});
    CHECK(find_receipt(*compiled, ReceiptKind::Rejected, reasons::kOverrideProhibited) != nullptr);
    CHECK(explanation_mentions(entry, "refused"));
  }

  // Authority-requiring override without authority: refused, and the omission is named.
  {
    SiteFixture fixture;
    Rule mandatory = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
    mandatory.override_permission = OverridePermission::AllowedWithAuthority;
    PolicyBundle bundle = fixture.global_bundle({mandatory}, Generation{1});
    const LocalOverride override_record =
        make_override(fixture.ids, fixture.federation, fixture.member, fixture.site, bundle.rules[0],
                      bundle, Generation{1}, int_value(90), "site-reliability", "delegated exception",
                      GrantId{}, fixture.now);

    EffectivePolicyInput without_ledger = fixture.input();
    without_ledger.accepted_bundles.push_back(bundle);
    without_ledger.overrides.push_back(override_record);
    auto compiled_without = compile_effective_policy(without_ledger);
    REQUIRE(compiled_without.ok());
    CHECK(compiled_without->find("power", "max_kw")->state == EntryState::Active);
    CHECK(find_receipt(*compiled_without, ReceiptKind::Rejected, reasons::kOverrideUnauthorized) != nullptr);

    // With a valid delegated override authority in scope the override applies.
    AuthorityLedger ledger(fixture.federation);
    ledger.set_root_member(fixture.operator_member);
    const AuthorityGrant root =
        make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.member, GrantId{},
                   AuthorityAction::Delegate, RuleScope::for_members({fixture.member}));
    REQUIRE(ledger.add_root_grant(root, fixture.now).ok());
    const AuthorityGrant override_authority =
        make_grant(fixture.ids, fixture.federation, fixture.member, fixture.member, root.id,
                   AuthorityAction::OverridePolicy, RuleScope::for_members({fixture.member}), {"power"});
    REQUIRE(ledger.add_grant(override_authority, fixture.now).ok());

    LocalOverride authorized = override_record;
    authorized.authority = override_authority.id;
    REQUIRE(seal_override(authorized).ok());
    EffectivePolicyInput with_ledger = fixture.input();
    with_ledger.authority = &ledger;
    with_ledger.membership = &fixture.membership;
    with_ledger.accepted_bundles.push_back(bundle);
    with_ledger.overrides.push_back(authorized);
    auto compiled_with = compile_effective_policy(with_ledger);
    if (!compiled_with.ok()) NOTE("compile failed: " + compiled_with.error.to_string());
    REQUIRE(compiled_with.ok());
    CHECK(compiled_with->find("power", "max_kw")->state == EntryState::Overridden);
    CHECK_EQ(compiled_with->find("power", "max_kw")->override_authority.to_string(),
             override_authority.id.to_string());

    // Citing an authority that is not held is refused rather than trusted.
    LocalOverride uncited = override_record;
    uncited.authority = make_grant_id(fixture.ids);
    REQUIRE(seal_override(uncited).ok());
    EffectivePolicyInput wrong_authority = fixture.input();
    wrong_authority.authority = &ledger;
    wrong_authority.membership = &fixture.membership;
    wrong_authority.accepted_bundles.push_back(bundle);
    wrong_authority.overrides.push_back(uncited);
    auto compiled_wrong = compile_effective_policy(wrong_authority);
    REQUIRE(compiled_wrong.ok());
    CHECK(compiled_wrong->find("power", "max_kw")->state == EntryState::Active);
    CHECK(find_receipt(*compiled_wrong, ReceiptKind::Rejected, reasons::kOverrideUnauthorized) != nullptr);
  }

  // Generation binding: an override written against an older rule is superseded, never applied.
  {
    SiteFixture fixture;
    Rule original = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
    original.override_permission = OverridePermission::Allowed;
    PolicyBundle first_bundle = fixture.global_bundle({original}, Generation{1});
    const LocalOverride stale_override =
        make_override(fixture.ids, fixture.federation, fixture.member, fixture.site,
                      first_bundle.rules[0], first_bundle, Generation{1}, int_value(90),
                      "site-reliability", "based on the older policy", GrantId{}, fixture.now);

    Rule revised = make_rule(fixture.ids, "power", "max_kw", int_value(120), RuleClass::Mandatory);
    revised.override_permission = OverridePermission::Allowed;
    PolicyBundle second_bundle = fixture.global_bundle({revised}, Generation{2});

    EffectivePolicyInput input = fixture.input();
    input.accepted_bundles.push_back(first_bundle);
    input.accepted_bundles.push_back(second_bundle);
    input.overrides.push_back(stale_override);
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    const EffectiveEntry& entry = *compiled->find("power", "max_kw");
    CHECK(entry.state == EntryState::Active);
    CHECK(entry.value == int_value(120));
    CHECK(find_receipt(*compiled, ReceiptKind::Superseded, reasons::kOverrideSuperseded) != nullptr);
    CHECK_EQ(compiled->overrides_applied, std::size_t{0});
  }

  // Overriding non-binding policy and overriding nothing at all are both refused.
  {
    SiteFixture fixture;
    Rule default_rule = make_rule(fixture.ids, "power", "max_kw", int_value(100));
    PolicyBundle bundle = fixture.global_bundle({default_rule}, Generation{1});
    const LocalOverride not_applicable =
        make_override(fixture.ids, fixture.federation, fixture.member, fixture.site, bundle.rules[0],
                      bundle, Generation{1}, int_value(90), "site-reliability", "wish", GrantId{},
                      fixture.now);
    Rule absent = make_rule(fixture.ids, "power", "unused_kw", int_value(1));
    const LocalOverride without_base =
        make_override(fixture.ids, fixture.federation, fixture.member, fixture.site, absent, bundle,
                      Generation{1}, int_value(1), "site-reliability", "no base", GrantId{}, fixture.now);

    EffectivePolicyInput input = fixture.input();
    input.accepted_bundles.push_back(bundle);
    input.overrides.push_back(not_applicable);
    input.overrides.push_back(without_base);
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    CHECK(find_receipt(*compiled, ReceiptKind::Rejected, reasons::kOverrideNotApplicable) != nullptr);
    CHECK(find_receipt(*compiled, ReceiptKind::Rejected, reasons::kOverrideWithoutBase) != nullptr);
    CHECK_EQ(compiled->overrides_refused, std::size_t{2});
  }

  // An expired override is refused.
  {
    SiteFixture fixture;
    Rule mandatory = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
    mandatory.override_permission = OverridePermission::Allowed;
    PolicyBundle bundle = fixture.global_bundle({mandatory}, Generation{1});
    const LocalOverride expired =
        make_override(fixture.ids, fixture.federation, fixture.member, fixture.site, bundle.rules[0],
                      bundle, Generation{1}, int_value(90), "site-reliability", "temporary exception",
                      GrantId{}, at(fixture.now.ms - kDay), at(fixture.now.ms - kHour));
    EffectivePolicyInput input = fixture.input();
    input.accepted_bundles.push_back(bundle);
    input.overrides.push_back(expired);
    auto compiled = compile_effective_policy(input);
    REQUIRE(compiled.ok());
    CHECK(find_receipt(*compiled, ReceiptKind::Rejected, reasons::kPolicyExpired) != nullptr);
    CHECK_EQ(compiled->overrides_refused, std::size_t{1});
  }
}

GPF_TEST(effective, explain_subject_distinguishes_absent_from_conflicted) {
  SiteFixture fixture;
  Rule left = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  Rule right = make_rule(fixture.ids, "power", "max_kw", int_value(120), RuleClass::Mandatory);
  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(fixture.global_bundle({left}, Generation{1}));
  input.accepted_bundles.push_back(
      fixture.global_bundle({right}, Generation{1}, StalenessPolicy::require_fresh(), Timestamp{0},
                            SemanticVersion{1, 0, 0}, Generation{1}, RuleScope::federation(),
                            fixture.second_operator_member));
  auto compiled = compile_effective_policy(input);
  REQUIRE(compiled.ok());

  const EffectiveEntry conflicted = explain_subject(*compiled, "power", "max_kw");
  CHECK(conflicted.state == EntryState::Conflicted);
  CHECK(!conflicted.conflict.is_nil());
  CHECK(conflicted.explanation.size() >= 1);

  const EffectiveEntry absent = explain_subject(*compiled, "power", "nothing_here");
  CHECK(absent.state == EntryState::Absent);
  CHECK(!entry_state_is_binding(absent.state));
  CHECK_EQ(absent.reason_code, std::string("no-policy-addresses-subject"));
  CHECK(explanation_mentions(absent, "absent"));
}

GPF_TEST(effective, effective_policy_json_round_trip_and_tamper_detection) {
  SiteFixture fixture;
  Rule mandatory = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  Rule advisory = make_rule(fixture.ids, "cooling", "mode", text_value("liquid"), RuleClass::Advisory);
  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(fixture.global_bundle({mandatory, advisory}, Generation{3}));
  auto compiled = compile_effective_policy(input);
  REQUIRE(compiled.ok());

  const std::string dumped = effective_policy_to_json(*compiled).dump();
  auto parsed = JsonValue::parse(dumped);
  REQUIRE(parsed.ok());
  auto restored = effective_policy_from_json(*parsed);
  if (!restored.ok()) NOTE("effective_policy_from_json: " + restored.error.to_string());
  REQUIRE(restored.ok());
  CHECK(restored->digest == compiled->digest);
  CHECK_EQ(restored->entries.size(), compiled->entries.size());
  CHECK_EQ(restored->receipts.size(), compiled->receipts.size());

  auto tampered = JsonValue::parse(dumped);
  REQUIRE(tampered.ok());
  JsonValue::Array entries = tampered->find("entries")->array_items();
  entries[0].set_field("state", JsonValue::text("active"));
  tampered->set_field("entries", JsonValue::array(std::move(entries)));
  CHECK(!effective_policy_from_json(*tampered).ok());
}

GPF_TEST(effective, compilation_limits_are_enforced) {
  SiteFixture fixture;
  std::vector<Rule> rules;
  for (int i = 0; i < 20; ++i) {
    rules.push_back(make_rule(fixture.ids, "domain" + std::to_string(i), "subject", int_value(i)));
  }
  EffectivePolicyInput input = fixture.input();
  input.accepted_bundles.push_back(fixture.global_bundle(std::move(rules), Generation{1}));
  input.max_rules = 5;
  auto compiled = compile_effective_policy(input);
  CHECK(!compiled.ok());
  CHECK_EQ(error_code_name(compiled.error.code), std::string("too-large"));

  input.max_rules = limits::kMaxRulesPerCompilation;
  CHECK(compile_effective_policy(input).ok());
}

GPF_TEST(effective, randomized_scoped_rules_compile_deterministically) {
  const std::uint64_t base_seed = 0x5DEECE66Dull;
  const char* domains[] = {"power", "cooling", "network"};
  const char* subjects[] = {"max_kw", "min_kw", "target_c", "mode"};
  std::size_t total_entries = 0;
  std::size_t total_conflicts = 0;
  std::size_t total_overrides = 0;

  for (int iteration = 0; iteration < 40; ++iteration) {
    const std::uint64_t case_seed = base_seed + static_cast<std::uint64_t>(iteration) * 7919ull;
    Rng rng(case_seed);
    SiteFixture fixture(case_seed % 100000 + 1);
    EffectivePolicyInput input = fixture.input();
    input.capability_catalog = fixture.catalog(Generation{2}, {{fixture.kMetering, SemanticVersion{2, 0, 0}}});
    input.capabilities = fixture.snapshot(Generation{2}, {{fixture.kMetering, SemanticVersion{2, 0, 0}}});

    std::vector<PolicyBundle> bundles;
    const std::size_t bundle_count = 1 + static_cast<std::size_t>(rng.below(3));
    for (std::size_t b = 0; b < bundle_count; ++b) {
      std::vector<Rule> rules;
      std::vector<std::string> seen_keys;
      const std::size_t rule_count = 1 + static_cast<std::size_t>(rng.below(6));
      for (std::size_t r = 0; r < rule_count; ++r) {
        const std::string domain = domains[rng.below(3)];
        const std::string subject = subjects[rng.below(4)];
        const std::uint32_t precedence = static_cast<std::uint32_t>(rng.below(2));
        const int class_pick = static_cast<int>(rng.below(3));
        const RuleClass rule_class =
            class_pick == 0 ? RuleClass::Advisory
                            : (class_pick == 1 ? RuleClass::Default : RuleClass::Mandatory);
        // Non-mandatory rules always carry precedence zero, so the de-duplication key must use
        // the effective precedence or it would author contradictory bundles.
        const std::uint32_t effective_precedence =
            rule_class == RuleClass::Mandatory ? precedence : 0u;
        const std::string dedupe = domain + "/" + subject + "#" + std::to_string(class_pick) + "#" +
                                   std::to_string(effective_precedence);
        if (std::find(seen_keys.begin(), seen_keys.end(), dedupe) != seen_keys.end()) continue;
        seen_keys.push_back(dedupe);

        const int scope_pick = static_cast<int>(rng.below(3));
        RuleScope scope = RuleScope::federation();
        if (scope_pick == 1) scope = RuleScope::for_members({fixture.member});
        if (scope_pick == 2) scope = RuleScope::for_sites({fixture.site});
        Rule rule = make_rule(fixture.ids, domain, subject,
                              rng.chance(1, 3) ? text_value("mode-" + std::to_string(rng.below(4)))
                                               : int_value(static_cast<std::int64_t>(rng.below(1000))),
                              rule_class, scope, effective_precedence);
        if (rule_class == RuleClass::Mandatory) {
          const int permission = static_cast<int>(rng.below(3));
          rule.override_permission = permission == 0 ? OverridePermission::Prohibited
                                                     : (permission == 1 ? OverridePermission::Allowed
                                                                        : OverridePermission::AllowedWithAuthority);
          if (rng.chance(1, 4)) {
            rule.staleness = StalenessPolicy::allow_last_known_valid(kDay);
          }
        }
        if (rng.chance(1, 4)) {
          const int requirement = static_cast<int>(rng.below(3));
          rule.capability_requirements.push_back(CapabilityRequirement{
              requirement == 0 ? "power.metering" : (requirement == 1 ? "cooling.liquid" : "fusion.reactor"),
              SemanticVersion{2, 0, 0}, rng.chance(1, 4)});
        }
        rules.push_back(std::move(rule));
      }
      const MemberId issuer =
          rng.chance(1, 2) ? fixture.operator_member : fixture.second_operator_member;
      bundles.push_back(
          fixture.global_bundle(std::move(rules), Generation{b + 1}, StalenessPolicy::require_fresh(),
                                Timestamp{0}, SemanticVersion{1, 0, 0}, Generation{1},
                                RuleScope::federation(), issuer));
    }
    input.accepted_bundles = bundles;
    if (rng.chance(1, 2)) {
      input.partitioned = true;
      input.last_contact_at = at(fixture.now.ms - static_cast<std::int64_t>(rng.below(3 * kDay)));
    }

    // One override, bound to a real rule from a real bundle, when a mandatory rule exists.
    for (const PolicyBundle& bundle : bundles) {
      for (const Rule& rule : bundle.rules) {
        if (rule.rule_class != RuleClass::Mandatory) continue;
        if (rule.override_permission == OverridePermission::Prohibited) continue;
        input.overrides.push_back(make_override(fixture.ids, fixture.federation, fixture.member,
                                               fixture.site, rule, bundle, Generation{2},
                                               int_value(1), "randomized-test", "property test override",
                                               GrantId{}, fixture.now));
        break;
      }
      if (!input.overrides.empty()) break;
    }

    auto first = compile_effective_policy(input);
    if (!first.ok()) {
      NOTE("case " + std::to_string(iteration) + " seed " + std::to_string(case_seed) +
           " failed to compile: " + first.error.to_string());
      CHECK(false);
      continue;
    }

    // Determinism across repeated compilation.
    auto second = compile_effective_policy(input);
    REQUIRE(second.ok());
    CHECK(first->digest == second->digest);
    CHECK_EQ(first->receipts.size(), second->receipts.size());

    // Determinism across policy arrival order.
    EffectivePolicyInput shuffled = input;
    std::reverse(shuffled.accepted_bundles.begin(), shuffled.accepted_bundles.end());
    auto third = compile_effective_policy(shuffled);
    REQUIRE(third.ok());
    CHECK(first->digest == third->digest);

    // Invariants that must hold for every compiled result.
    std::uint64_t previous_sequence = 0;
    for (const Receipt& receipt : first->receipts) {
      CHECK(receipt.sequence.value == previous_sequence + 1);
      previous_sequence = receipt.sequence.value;
      CHECK(validate_receipt(receipt).ok());
    }
    for (const EffectiveEntry& entry : first->entries) {
      if (entry_state_is_binding(entry.state)) {
        CHECK(!entry.source_rule.is_nil());
        CHECK(!entry.source_bundle.is_nil());
      }
      if (entry.state == EntryState::Conflicted) CHECK(!entry.conflict.is_nil());
      if (entry.state == EntryState::Overridden) CHECK(!entry.applied_override.is_nil());
      CHECK(!entry.explanation.empty());
    }
    for (const ConflictRecord& conflict : first->conflicts) {
      CHECK(conflict.participants.size() >= 2);
      CHECK(conflict.contained);
      CHECK(validate_conflict(conflict).ok());
    }
    CHECK(validate_effective_policy(*first).ok());
    total_entries += first->entries.size();
    total_conflicts += first->conflicts.size();
    total_overrides += first->overrides_applied;
  }
  NOTE("randomized compilation produced " + std::to_string(total_entries) + " entries, " +
       std::to_string(total_conflicts) + " conflicts, " + std::to_string(total_overrides) +
       " applied overrides");
  CHECK(total_entries > 0);
}
