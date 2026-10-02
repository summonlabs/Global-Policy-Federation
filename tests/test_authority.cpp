#include "fixtures.hpp"
#include "test_support.hpp"

#include <string>

using namespace gpf;
using namespace gpf_test;

namespace {

struct AuthorityFixture {
  IdGenerator ids{101};
  FederationId federation = make_federation(ids);
  MemberId root = make_member(ids);
  MemberId operator_member = make_member(ids);
  MemberId site_member = make_member(ids);
  SiteId site = make_site(ids);
  SiteId foreign_site = make_site(ids);
  Timestamp now = at(100 * kDay);
  MembershipBinding membership{{std::make_pair(site_member, site)}};

  AuthorityLedger make_ledger() const {
    AuthorityLedger ledger(federation);
    ledger.set_root_member(root);
    return ledger;
  }

  AuthorityGrant root_grant() {
    return make_grant(ids, federation, root, operator_member, GrantId{}, AuthorityAction::Delegate,
                      RuleScope::federation());
  }
};

}  // namespace

GPF_TEST(authority, root_grant_bootstrap_is_explicit_and_once) {
  AuthorityFixture fixture;
  AuthorityLedger ledger = fixture.make_ledger();

  const AuthorityGrant wrong_issuer = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.operator_member, GrantId{},
      AuthorityAction::Delegate, RuleScope::federation());
  CHECK(!ledger.add_root_grant(wrong_issuer, fixture.now).ok());

  const AuthorityGrant wrong_action = make_grant(
      fixture.ids, fixture.federation, fixture.root, fixture.operator_member, GrantId{},
      AuthorityAction::PublishMandatory, RuleScope::federation());
  CHECK(!ledger.add_root_grant(wrong_action, fixture.now).ok());

  const AuthorityGrant root = fixture.root_grant();
  REQUIRE(ledger.add_root_grant(root, fixture.now).ok());
  CHECK_EQ(ledger.root_grant().to_string(), root.id.to_string());

  const AuthorityGrant second_root = make_grant(
      fixture.ids, fixture.federation, fixture.root, fixture.site_member, GrantId{},
      AuthorityAction::Delegate, RuleScope::federation());
  auto second_status = ledger.add_root_grant(second_root, fixture.now);
  CHECK(!second_status.ok());
  CHECK_EQ(error_code_name(second_status.error.code), std::string("already-exists"));

  const AuthorityGrant expired = make_grant(
      fixture.ids, fixture.federation, fixture.root, fixture.operator_member, GrantId{},
      AuthorityAction::Delegate, RuleScope::federation(), {}, at(0), at(50 * kDay));
  AuthorityLedger other = fixture.make_ledger();
  CHECK(!other.add_root_grant(expired, fixture.now).ok());

  AuthorityGrant tampered = root;
  tampered.scope = RuleScope::for_sites({fixture.site});
  AuthorityLedger third = fixture.make_ledger();
  auto tampered_status = third.add_root_grant(tampered, fixture.now);
  CHECK(!tampered_status.ok());
  CHECK_EQ(error_code_name(tampered_status.error.code), std::string("integrity-failure"));
}

GPF_TEST(authority, delegation_can_only_be_narrowed) {
  AuthorityFixture fixture;
  AuthorityLedger ledger = fixture.make_ledger();
  const AuthorityGrant root = fixture.root_grant();
  REQUIRE(ledger.add_root_grant(root, fixture.now).ok());

  // Legitimate narrowing: a member-scoped delegation limited to one conflict domain.
  const AuthorityGrant middle =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
                 AuthorityAction::Delegate, RuleScope::for_members({fixture.site_member}), {"power"});
  REQUIRE(ledger.add_grant(middle, fixture.now).ok());

  // A site-scoped child of the member-scoped delegation needs the membership binding.
  const AuthorityGrant site_child = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.site_member, middle.id,
      AuthorityAction::PublishMandatory, RuleScope::for_sites({fixture.site}), {"power"});
  CHECK(!ledger.add_grant(site_child, fixture.now).ok());  // cannot be established without membership
  CHECK(ledger.add_grant(site_child, fixture.now, &fixture.membership).ok());

  // The binding does not let a member claim somebody else's site.
  const AuthorityGrant foreign_child = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.site_member, middle.id,
      AuthorityAction::PublishMandatory, RuleScope::for_sites({fixture.foreign_site}), {"power"});
  auto foreign_status = ledger.add_grant(foreign_child, fixture.now, &fixture.membership);
  CHECK(!foreign_status.ok());
  CHECK_EQ(error_code_name(foreign_status.error.code), std::string("forbidden"));

  // Widening the scope back to the whole federation is refused.
  const AuthorityGrant wider = make_grant(fixture.ids, fixture.federation, fixture.site_member,
                                          fixture.site_member, middle.id, AuthorityAction::PublishMandatory,
                                          RuleScope::federation(), {"power"});
  auto wider_status = ledger.add_grant(wider, fixture.now, &fixture.membership);
  CHECK(!wider_status.ok());
  CHECK_EQ(error_code_name(wider_status.error.code), std::string("forbidden"));

  // Widening the conflict-domain list is refused.
  const AuthorityGrant wider_domains = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.site_member, middle.id,
      AuthorityAction::PublishMandatory, RuleScope::for_members({fixture.site_member}),
      {"power", "cooling"});
  CHECK(!ledger.add_grant(wider_domains, fixture.now).ok());

  // Dropping the domain restriction is refused.
  const AuthorityGrant dropped_domains = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.site_member, middle.id,
      AuthorityAction::PublishMandatory, RuleScope::for_members({fixture.site_member}), {});
  auto dropped_status = ledger.add_grant(dropped_domains, fixture.now);
  CHECK(!dropped_status.ok());
  CHECK_EQ(error_code_name(dropped_status.error.code), std::string("forbidden"));

  // A grantor who does not hold the parent grant cannot issue.
  const AuthorityGrant impersonated = make_grant(
      fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, middle.id,
      AuthorityAction::PublishPolicy, RuleScope::for_members({fixture.site_member}), {});
  CHECK(!ledger.add_grant(impersonated, fixture.now).ok());

  // A non-delegating parent cannot delegate.
  const AuthorityGrant leaf = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.site_member, middle.id,
      AuthorityAction::PublishPolicy, RuleScope::for_members({fixture.site_member}), {"power"});
  REQUIRE(ledger.add_grant(leaf, fixture.now).ok());
  const AuthorityGrant from_leaf = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.operator_member, leaf.id,
      AuthorityAction::PublishPolicy, RuleScope::for_members({fixture.site_member}), {"power"});
  CHECK(!ledger.add_grant(from_leaf, fixture.now).ok());

  // An unknown parent is a missing link, not an implicit grant.
  const AuthorityGrant orphan =
      make_grant(fixture.ids, fixture.federation, fixture.site_member, fixture.operator_member,
                 make_grant_id(fixture.ids), AuthorityAction::PublishPolicy,
                 RuleScope::for_members({fixture.site_member}), {});
  CHECK(!ledger.add_grant(orphan, fixture.now).ok());

  // Re-applying the identical grant is idempotent; a different grant under the same identity is
  // a conflict rather than a silent replacement.
  CHECK(ledger.add_grant(middle, fixture.now).ok());
  AuthorityGrant impostor = middle;
  impostor.scope = RuleScope::federation();
  REQUIRE(seal_grant(impostor).ok());
  auto impostor_status = ledger.add_grant(impostor, fixture.now);
  CHECK(!impostor_status.ok());
  CHECK_EQ(error_code_name(impostor_status.error.code), std::string("already-exists"));
}

GPF_TEST(authority, evaluation_reports_distinct_failures) {
  AuthorityFixture fixture;
  AuthorityLedger ledger = fixture.make_ledger();
  const AuthorityGrant root = fixture.root_grant();
  REQUIRE(ledger.add_root_grant(root, fixture.now).ok());

  const RuleScope site_scope = RuleScope::for_sites({fixture.site});
  const RuleScope foreign_scope = RuleScope::for_sites({fixture.foreign_site});

  // Membership alone grants nothing.
  auto decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope,
                                  "power", fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::NoGrant);
  CHECK(!decision.granted());

  const AuthorityGrant mandatory_grant = make_grant(
      fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
      AuthorityAction::PublishMandatory, RuleScope::for_members({fixture.site_member}), {"power"});
  REQUIRE(ledger.add_grant(mandatory_grant, fixture.now).ok());

  decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope, "power",
                             fixture.now, &fixture.membership);
  CHECK(decision.granted());
  CHECK_EQ(decision.grant.to_string(), mandatory_grant.id.to_string());

  // Without the membership binding the member-scoped grant cannot be resolved to the site.
  decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope, "power",
                             fixture.now);
  CHECK(decision.outcome == AuthorityOutcome::OutOfScope);

  // A different action needs its own grant.
  decision = ledger.evaluate(fixture.site_member, AuthorityAction::OverridePolicy, site_scope, "power",
                             fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::NoGrant);

  // Scope outside the grant: the site is not bound to the granting member.
  decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishMandatory, foreign_scope,
                             "power", fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::OutOfScope);

  // Domain outside the grant.
  decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope,
                             "cooling", fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::DomainNotCovered);

  // Expiry is reported as expiry, not as absence.
  const AuthorityGrant expiring = make_grant(
      fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
      AuthorityAction::PublishPolicy, RuleScope::for_members({fixture.site_member}), {"power"}, at(0),
      at(50 * kDay));
  REQUIRE(ledger.add_grant(expiring, fixture.now).ok());
  decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishPolicy, site_scope, "power",
                             fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::Expired);

  const AuthorityGrant future = make_grant(
      fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
      AuthorityAction::Revoke, RuleScope::for_members({fixture.site_member}), {"power"}, at(150 * kDay));
  REQUIRE(ledger.add_grant(future, fixture.now).ok());
  decision = ledger.evaluate(fixture.site_member, AuthorityAction::Revoke, site_scope, "power",
                             fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::NotYetValid);
  CHECK(ledger.evaluate(fixture.site_member, AuthorityAction::Revoke, site_scope, "power", at(160 * kDay),
                        &fixture.membership)
            .granted());
}

GPF_TEST(authority, revocation_invalidates_descendants_and_is_ordered) {
  AuthorityFixture fixture;
  AuthorityLedger ledger = fixture.make_ledger();
  const AuthorityGrant root = fixture.root_grant();
  REQUIRE(ledger.add_root_grant(root, fixture.now).ok());

  const AuthorityGrant middle =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
                 AuthorityAction::Delegate, RuleScope::for_members({fixture.site_member}));
  REQUIRE(ledger.add_grant(middle, fixture.now).ok());
  const AuthorityGrant leaf = make_grant(
      fixture.ids, fixture.federation, fixture.site_member, fixture.site_member, middle.id,
      AuthorityAction::PublishMandatory, RuleScope::for_members({fixture.site_member}), {});
  REQUIRE(ledger.add_grant(leaf, fixture.now).ok());

  const RuleScope site_scope = RuleScope::for_sites({fixture.site});
  CHECK(ledger
            .evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope, "power",
                      fixture.now, &fixture.membership)
            .granted());

  // Revoking the middle grant invalidates the leaf's chain.
  const RevocationRecord revocation =
      make_revocation(fixture.ids, fixture.federation, RevocationTarget::Grant, middle.id.value,
                      fixture.root, "root-operator", GrantId{}, 1, fixture.now, "delegation withdrawn");
  REQUIRE(ledger.add_revocation(revocation, fixture.now).ok());
  auto decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope,
                                  "power", fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::Revoked);
  CHECK_EQ(ledger.verify_chain(leaf.id, fixture.now, &fixture.membership).outcome,
           AuthorityOutcome::Revoked);

  // Reordered or replayed revocation sequences are refused.
  const RevocationRecord replay =
      make_revocation(fixture.ids, fixture.federation, RevocationTarget::Grant, middle.id.value,
                      fixture.root, "root-operator", GrantId{}, 1, fixture.now);
  auto replay_status = ledger.add_revocation(replay, fixture.now);
  CHECK(!replay_status.ok());
  CHECK_EQ(error_code_name(replay_status.error.code), std::string("reordered"));

  // A non-root member cannot revoke without a delegation.
  const RevocationRecord unauthorized =
      make_revocation(fixture.ids, fixture.federation, RevocationTarget::Bundle,
                      make_bundle_id(fixture.ids).value, fixture.site_member, "site-operator", GrantId{},
                      2, fixture.now);
  auto unauthorized_status = ledger.add_revocation(unauthorized, fixture.now);
  CHECK(!unauthorized_status.ok());
  CHECK_EQ(error_code_name(unauthorized_status.error.code), std::string("unauthorized"));

  // A delegated revocation authority works, and its effect is time-bounded.
  const AuthorityGrant revoker =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
                 AuthorityAction::Revoke, RuleScope::for_members({fixture.site_member}), {});
  REQUIRE(ledger.add_grant(revoker, fixture.now).ok());
  const PolicyBundleId target = make_bundle_id(fixture.ids);
  RevocationRecord scheduled =
      make_revocation(fixture.ids, fixture.federation, RevocationTarget::Bundle, target.value,
                      fixture.site_member, "site-operator", revoker.id, 3, fixture.now);
  scheduled.effective_at = at(200 * kDay);
  REQUIRE(seal_revocation(scheduled).ok());
  REQUIRE(ledger.add_revocation(scheduled, fixture.now).ok());
  CHECK(!ledger.is_bundle_revoked(target, fixture.now));
  CHECK(ledger.is_bundle_revoked(target, at(200 * kDay)));

  // A revocation authority whose grant does not cover the target scope is refused.
  const AuthorityGrant narrow_revoker =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
                 AuthorityAction::Revoke, RuleScope::for_members({fixture.site_member}), {});
  REQUIRE(ledger.add_grant(narrow_revoker, fixture.now).ok());
  const RevocationRecord out_of_scope =
      make_revocation(fixture.ids, fixture.federation, RevocationTarget::Grant, root.id.value,
                      fixture.site_member, "site-operator", narrow_revoker.id, 4, fixture.now);
  CHECK(!ledger.add_revocation(out_of_scope, fixture.now).ok());
}

GPF_TEST(authority, epoch_advance_fences_stale_grants_and_allows_recovery) {
  AuthorityFixture fixture;
  AuthorityLedger ledger = fixture.make_ledger();
  const AuthorityGrant root = fixture.root_grant();
  REQUIRE(ledger.add_root_grant(root, fixture.now).ok());
  const AuthorityGrant grant =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
                 AuthorityAction::PublishMandatory, RuleScope::for_members({fixture.site_member}), {});
  REQUIRE(ledger.add_grant(grant, fixture.now).ok());
  const RuleScope site_scope = RuleScope::for_sites({fixture.site});
  CHECK(ledger
            .evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope, "power",
                      fixture.now, &fixture.membership)
            .granted());

  REQUIRE(ledger.advance_epoch(fixture.now).ok());
  auto decision = ledger.evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope,
                                  "power", fixture.now, &fixture.membership);
  CHECK(decision.outcome == AuthorityOutcome::EpochFenced);
  CHECK_EQ(ledger.verify_chain(root.id, fixture.now).outcome, AuthorityOutcome::EpochFenced);

  // Recovery: re-establish the root under the new epoch, then delegate again.
  const AuthorityGrant root_again =
      make_grant(fixture.ids, fixture.federation, fixture.root, fixture.operator_member, GrantId{},
                 AuthorityAction::Delegate, RuleScope::federation(), {}, at(0), at(0), ledger.epoch());
  REQUIRE(ledger.add_root_grant(root_again, fixture.now).ok());
  const AuthorityGrant regranted =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member,
                 root_again.id, AuthorityAction::PublishMandatory,
                 RuleScope::for_members({fixture.site_member}), {}, at(0), at(0), ledger.epoch());
  REQUIRE(ledger.add_grant(regranted, fixture.now).ok());
  CHECK(ledger
            .evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope, "power",
                      fixture.now, &fixture.membership)
            .granted());
  CHECK_EQ(ledger.verify_chain(root.id, fixture.now).outcome, AuthorityOutcome::EpochFenced);
}

GPF_TEST(authority, ledger_restore_validates_persisted_state) {
  AuthorityFixture fixture;
  AuthorityLedger ledger = fixture.make_ledger();
  const AuthorityGrant root = fixture.root_grant();
  REQUIRE(ledger.add_root_grant(root, fixture.now).ok());
  const AuthorityGrant grant =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member, root.id,
                 AuthorityAction::PublishMandatory, RuleScope::for_members({fixture.site_member}), {});
  REQUIRE(ledger.add_grant(grant, fixture.now).ok());
  const RevocationRecord revocation =
      make_revocation(fixture.ids, fixture.federation, RevocationTarget::Grant, grant.id.value,
                      fixture.root, "root-operator", GrantId{}, 1, fixture.now);
  REQUIRE(ledger.add_revocation(revocation, fixture.now).ok());

  AuthorityLedger restored(fixture.federation);
  restored.set_root_member(fixture.root);
  CHECK(restored.restore(ledger.grants(), ledger.revocations(), ledger.epoch(), fixture.now).ok());
  CHECK_EQ(restored.root_grant().to_string(), root.id.to_string());
  CHECK(restored.is_grant_revoked(grant.id, fixture.now));
  const RuleScope site_scope = RuleScope::for_sites({fixture.site});
  CHECK(restored
            .evaluate(fixture.site_member, AuthorityAction::PublishMandatory, site_scope, "power",
                      fixture.now, &fixture.membership)
            .outcome == AuthorityOutcome::Revoked);

  // Digest tampering is detected on restore.
  std::vector<AuthorityGrant> tampered_grants = ledger.grants();
  tampered_grants[1].conflict_domains = {"power"};
  AuthorityLedger other(fixture.federation);
  other.set_root_member(fixture.root);
  auto tampered_status = other.restore(tampered_grants, ledger.revocations(), ledger.epoch(), fixture.now);
  CHECK(!tampered_status.ok());
  CHECK_EQ(error_code_name(tampered_status.error.code), std::string("integrity-failure"));

  // Two root grants in persisted state are a defect, not a preference.
  std::vector<AuthorityGrant> two_roots = ledger.grants();
  two_roots.push_back(make_grant(fixture.ids, fixture.federation, fixture.root, fixture.operator_member,
                                 GrantId{}, AuthorityAction::Delegate, RuleScope::federation()));
  AuthorityLedger third(fixture.federation);
  third.set_root_member(fixture.root);
  CHECK(!third.restore(two_roots, ledger.revocations(), ledger.epoch(), fixture.now).ok());

  // Out-of-order revocations in persisted state are refused rather than silently re-sorted.
  std::vector<RevocationRecord> unordered;
  unordered.push_back(make_revocation(fixture.ids, fixture.federation, RevocationTarget::Rule,
                                      make_rule_id(fixture.ids).value, fixture.root, "root-operator",
                                      GrantId{}, 5, fixture.now));
  unordered.push_back(make_revocation(fixture.ids, fixture.federation, RevocationTarget::Rule,
                                      make_rule_id(fixture.ids).value, fixture.root, "root-operator",
                                      GrantId{}, 4, fixture.now));
  AuthorityLedger fourth(fixture.federation);
  fourth.set_root_member(fixture.root);
  auto unordered_status = fourth.restore(ledger.grants(), unordered, ledger.epoch(), fixture.now);
  CHECK(!unordered_status.ok());
  CHECK_EQ(error_code_name(unordered_status.error.code), std::string("reordered"));
}

GPF_TEST(authority, membership_binding_is_validated) {
  AuthorityFixture fixture;
  CHECK(validate_membership_binding(fixture.membership).ok());
  CHECK(fixture.membership.contains(fixture.site_member, fixture.site));
  CHECK(!fixture.membership.contains(fixture.operator_member, fixture.site));

  MembershipBinding conflicting{{std::make_pair(fixture.site_member, fixture.site),
                                std::make_pair(fixture.operator_member, fixture.site)}};
  auto status = validate_membership_binding(conflicting);
  CHECK(!status.ok());
  CHECK_EQ(error_code_name(status.error.code), std::string("conflict"));

  MembershipBinding nil_member{{std::make_pair(MemberId{}, fixture.site)}};
  CHECK(!validate_membership_binding(nil_member).ok());
  MembershipBinding nil_site{{std::make_pair(fixture.site_member, SiteId{})}};
  CHECK(!validate_membership_binding(nil_site).ok());
  CHECK(validate_membership_binding(MembershipBinding{}).ok());
}

GPF_TEST(authority, grant_and_revocation_json_round_trip) {
  AuthorityFixture fixture;
  const AuthorityGrant grant =
      make_grant(fixture.ids, fixture.federation, fixture.operator_member, fixture.site_member,
                 make_grant_id(fixture.ids), AuthorityAction::OverridePolicy,
                 RuleScope::for_sites({fixture.site}), {"power", "cooling"}, at(0), at(0), Epoch{},
                 "delegated override authority for the site");
  auto parsed_json = JsonValue::parse(grant_to_json(grant).dump());
  REQUIRE(parsed_json.ok());
  auto restored = grant_from_json(*parsed_json);
  if (!restored.ok()) NOTE("grant_from_json: " + restored.error.to_string());
  REQUIRE(restored.ok());
  CHECK(restored->digest == grant.digest);
  CHECK_EQ(restored->conflict_domains.size(), std::size_t{2});

  auto tampered = JsonValue::parse(grant_to_json(grant).dump());
  REQUIRE(tampered.ok());
  tampered->set_field("action", JsonValue::text("revoke"));
  CHECK(!grant_from_json(*tampered).ok());

  const PolicyBundleId target = make_bundle_id(fixture.ids);
  const RevocationRecord revocation =
      make_revocation(fixture.ids, fixture.federation, RevocationTarget::Bundle, target.value,
                      fixture.root, "root-operator", GrantId{}, 7, fixture.now, "compromised");
  auto revocation_json = JsonValue::parse(revocation_to_json(revocation).dump());
  REQUIRE(revocation_json.ok());
  auto restored_revocation = revocation_from_json(*revocation_json);
  REQUIRE(restored_revocation.ok());
  CHECK_EQ(restored_revocation->target_bundle().to_string(), target.to_string());
  CHECK(restored_revocation->target_grant().is_nil());

  // A revocation naming the wrong identity kind is refused.
  auto wrong_kind = JsonValue::parse(revocation_to_json(revocation).dump());
  REQUIRE(wrong_kind.ok());
  wrong_kind->set_field("target_id", JsonValue::text(make_rule_id(fixture.ids).to_string()));
  CHECK(!revocation_from_json(*wrong_kind).ok());
}
