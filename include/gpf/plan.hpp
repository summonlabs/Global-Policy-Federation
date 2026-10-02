#pragma once
// Global Policy Federation — federation plan files and deterministic scenario generation.
//
// A plan is the declarative input of a federation run: identities, membership truth, capability
// catalog, delegated authority, and the policy bundles to publish. It contains no executable
// directives, which keeps runtime behavior a function of data rather than of a script.

#include "gpf/authority.hpp"
#include "gpf/effective.hpp"
#include "gpf/policy.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace gpf {

inline constexpr std::uint32_t kPlanFormatVersion = 1;

struct PlanSite {
  MemberId member;
  SiteId site;
};

struct FederationPlan {
  std::uint32_t format_version{kPlanFormatVersion};
  FederationId federation;
  MemberId root_member;
  SiteId coordinator_site;
  CapabilityCatalog catalog;
  MembershipBinding membership;
  std::vector<AuthorityGrant> grants;
  std::vector<PolicyBundle> bundles;
  std::vector<RevocationRecord> revocations;
  std::vector<PlanSite> sites;
};

Status validate_plan(const FederationPlan& plan);

JsonValue plan_to_json(const FederationPlan& plan);
Result<FederationPlan> plan_from_json(const JsonValue& value);

Result<FederationPlan> load_plan(const std::filesystem::path& path);
Status save_plan(const FederationPlan& plan, const std::filesystem::path& path);

// Deterministic scenario: the same seed and site count always produce a byte-identical plan, so a
// failing run can be reproduced exactly from the seed the driver prints.
Result<FederationPlan> generate_scenario(std::uint64_t seed, std::size_t site_count,
                                         std::size_t bundles_per_publisher);

// Binds a local override to the exact rule, bundle and generation that currently govern a subject
// for a site, as the compiled effective policy reports them.
Result<LocalOverride> make_override_for_subject(IdGenerator& ids, const FederationPlan& plan,
                                                const PlanSite& site, const EffectivePolicy& policy,
                                                const std::string& domain, const std::string& subject,
                                                SettingValue value, GrantId authority,
                                                const std::string& author, const std::string& reason,
                                                Timestamp now, Generation local_generation);

}  // namespace gpf
