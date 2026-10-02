#pragma once
// Global Policy Federation — delegated authority.
//
// Federation membership grants nothing by itself. Every right to publish, delegate, revoke or
// override policy is an explicit grant with a scope, a conflict-domain limit, a validity window
// and a parent grant that the runtime verifies before the right is honored.
//
// Validity is derived, never stored as a mutable flag: a grant is usable only while its whole
// chain up to the federation root grant is present, unrevoked, unexpired and scope-narrowing.

#include "gpf/base.hpp"
#include "gpf/codec.hpp"
#include "gpf/policy.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace gpf {

// Each action is a separate right. Publishing binding policy and publishing advisory policy are
// deliberately not the same grant.
enum class AuthorityAction : std::uint8_t {
  Delegate = 0,          // may create narrower child grants
  PublishPolicy = 1,     // may publish default and advisory policy
  PublishMandatory = 2,  // may publish mandatory policy
  Revoke = 3,            // may revoke grants, bundles and rules in scope
  OverridePolicy = 4,    // may register a local override of mandatory policy in scope
};

const char* authority_action_name(AuthorityAction value) noexcept;
Result<AuthorityAction> authority_action_from_name(std::string_view name);

struct AuthorityGrant {
  GrantId id;
  FederationId federation;
  MemberId grantor;
  MemberId grantee;
  GrantId parent;  // nil only for the federation root grant
  AuthorityAction action{AuthorityAction::PublishPolicy};
  RuleScope scope{};
  // Empty means "every conflict domain in scope". A non-empty list restricts the grant.
  std::vector<std::string> conflict_domains;
  Timestamp not_before{};
  Timestamp not_after{};    // zero means "no declared expiry"
  Epoch authority_epoch{};  // epoch in force when the grant was issued
  std::string justification;
  Digest digest{};  // computed and verified

  bool covers_domain(std::string_view domain) const noexcept;
  bool is_time_valid_at(Timestamp now) const noexcept;
};

Status validate_grant(const AuthorityGrant& grant);
Status seal_grant(AuthorityGrant& grant);
Result<Digest> compute_grant_digest(const AuthorityGrant& grant);

// ---------------------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------------------

enum class RevocationTarget : std::uint8_t {
  Grant = 0,
  Bundle = 1,
  Rule = 2,
};

const char* revocation_target_name(RevocationTarget value) noexcept;
Result<RevocationTarget> revocation_target_from_name(std::string_view name);

struct RevocationRecord {
  RevocationId id;
  FederationId federation;
  RevocationTarget target{RevocationTarget::Grant};
  Id128 target_id;  // interpreted according to the target kind
  MemberId actor_member;
  std::string actor;
  GrantId authority;  // the delegation that permitted this revocation (nil for root authority)
  Epoch authority_epoch{};
  SequenceNumber sequence{};  // total order of revocations per federation
  Timestamp issued_at{};
  Timestamp effective_at{};
  std::string reason;
  Digest digest{};

  bool is_effective_at(Timestamp now) const noexcept { return now.ms >= effective_at.ms; }
  GrantId target_grant() const;
  PolicyBundleId target_bundle() const;
  RuleId target_rule() const;
};

Status validate_revocation(const RevocationRecord& record);
Status seal_revocation(RevocationRecord& record);
Result<Digest> compute_revocation_digest(const RevocationRecord& record);

// ---------------------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------------------

enum class AuthorityOutcome : std::uint8_t {
  Granted = 0,
  NoGrant = 1,           // the member holds no grant for this action
  OutOfScope = 2,        // a grant exists, but not for this scope
  DomainNotCovered = 3,  // a grant exists, but the conflict domain is outside it
  NotYetValid = 4,
  Expired = 5,
  Revoked = 6,  // the grant or one of its ancestors was revoked
  BrokenChain = 7,  // the chain does not reach the federation root grant
  EpochFenced = 8,  // the grant belongs to a superseded authority epoch
};

const char* authority_outcome_name(AuthorityOutcome value) noexcept;

struct AuthorityDecision {
  AuthorityOutcome outcome{AuthorityOutcome::NoGrant};
  GrantId grant;
  std::string detail;

  bool granted() const noexcept { return outcome == AuthorityOutcome::Granted; }
};

// ---------------------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------------------

class AuthorityLedger {
 public:
  AuthorityLedger() = default;
  explicit AuthorityLedger(FederationId federation);

  FederationId federation() const noexcept { return federation_; }
  void set_federation(FederationId federation) noexcept { federation_ = federation; }

  // Trust anchor: the member identity that stands for the federation root authority. It is
  // configuration, never inferred from membership.
  MemberId root_member() const noexcept { return root_member_; }
  void set_root_member(MemberId member) noexcept { root_member_ = member; }
  GrantId root_grant() const noexcept { return root_grant_; }

  Epoch epoch() const noexcept { return epoch_; }
  // Bumping the epoch fences every grant issued under an older epoch. Used when the root
  // authority is re-established after a compromise.
  Result<Epoch> advance_epoch(Timestamp now);

  const std::vector<AuthorityGrant>& grants() const noexcept { return grants_; }
  const std::vector<RevocationRecord>& revocations() const noexcept { return revocations_; }

  // Bootstrap: exactly one root grant per federation, action Delegate, no parent.
  Status add_root_grant(const AuthorityGrant& grant, Timestamp now);
  Status add_grant(const AuthorityGrant& grant, Timestamp now,
                   const MembershipBinding* membership = nullptr);
  Status add_revocation(const RevocationRecord& record, Timestamp now,
                        const MembershipBinding* membership = nullptr);

  const AuthorityGrant* find_grant(GrantId id) const noexcept;
  bool is_grant_revoked(GrantId id, Timestamp now) const noexcept;
  bool is_bundle_revoked(PolicyBundleId id, Timestamp now) const noexcept;
  bool is_rule_revoked(RuleId id, Timestamp now) const noexcept;
  const RevocationRecord* find_revocation_for_grant(GrantId id) const noexcept;

  // Verified chain from the grant up to the root. Returns the outcome of the first broken link.
  // The membership binding is only needed while a member-scoped grant has to be resolved against
  // a site-scoped child or request.
  AuthorityDecision verify_chain(GrantId id, Timestamp now,
                                 const MembershipBinding* membership = nullptr) const;

  AuthorityDecision evaluate(MemberId member, AuthorityAction action, const RuleScope& scope,
                             std::string_view domain, Timestamp now,
                             const MembershipBinding* membership = nullptr) const;

  // Restores the ledger from a persisted snapshot. The caller is responsible for feeding events
  // in their original order; ordering here is enforced by the revocation sequence.
  Status restore(std::vector<AuthorityGrant> grants, std::vector<RevocationRecord> revocations,
                 Epoch epoch, Timestamp now);

 private:
  void index_grant(const AuthorityGrant& grant);
  void index_revocation(const RevocationRecord& record);

  FederationId federation_{};
  MemberId root_member_{};
  Epoch epoch_{};
  std::vector<AuthorityGrant> grants_;
  std::vector<RevocationRecord> revocations_;
  std::vector<GrantId> revoked_grants_;
  std::vector<PolicyBundleId> revoked_bundles_;
  std::vector<RuleId> revoked_rules_;
  GrantId root_grant_{};
  SequenceNumber last_revocation_sequence_{};
};

// ---------------------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------------------

JsonValue grant_to_json(const AuthorityGrant& grant);
Result<AuthorityGrant> grant_from_json(const JsonValue& value);

JsonValue revocation_to_json(const RevocationRecord& record);
Result<RevocationRecord> revocation_from_json(const JsonValue& value);

}  // namespace gpf
