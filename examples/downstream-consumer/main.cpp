// Downstream consumer of the installed Global Policy Federation package.
//
// This program is deliberately ordinary: it includes the public headers, links the exported
// namespaced target found by find_package, and exercises the documented API. It is built from a
// clean directory against an installed prefix, never against the build tree.

#include "gpf/effective.hpp"
#include "gpf/policy.hpp"

#include <cstdio>
#include <string>

namespace {

gpf::Rule make_rule(gpf::IdGenerator& ids, const std::string& domain, const std::string& subject,
                    std::int64_t value, gpf::RuleClass rule_class) {
  gpf::Rule rule;
  rule.id.value = ids.next();
  rule.version = gpf::SemanticVersion{1, 0, 0};
  rule.domain = domain;
  rule.subject = subject;
  rule.rule_class = rule_class;
  rule.scope = gpf::RuleScope::federation();
  rule.value = gpf::SettingValue::integer_value(value);
  return rule;
}

}  // namespace

int main() {
  gpf::IdGenerator ids(20260101);
  gpf::FederationId federation;
  federation.value = ids.next();
  gpf::MemberId member;
  member.value = ids.next();
  gpf::SiteId site;
  site.value = ids.next();

  std::vector<gpf::Rule> rules;
  rules.push_back(make_rule(ids, "power", "max_kw", 100, gpf::RuleClass::Mandatory));
  rules.push_back(make_rule(ids, "cooling", "target_c", 24, gpf::RuleClass::Default));
  rules.push_back(make_rule(ids, "network", "preferred_path", 7, gpf::RuleClass::Advisory));

  gpf::PolicyBundle bundle;
  bundle.id.value = ids.next();
  bundle.federation = federation;
  bundle.global_generation = gpf::Generation{1};
  bundle.issuer_member = member;
  bundle.scope = gpf::RuleScope::federation();
  bundle.issued_at = gpf::Timestamp{1700000000000};
  bundle.effective_from = bundle.issued_at;
  bundle.required_runtime = gpf::SemanticVersion{1, 0, 0};
  bundle.capability_catalog_generation = gpf::Generation{1};
  bundle.rules = std::move(rules);

  gpf::ProvenanceEntry provenance;
  provenance.actor = "downstream-consumer";
  provenance.member = member;
  provenance.generation = bundle.global_generation;
  provenance.at = bundle.issued_at;
  provenance.note = "published by the downstream consumer validation";
  provenance.entry_digest = *gpf::compute_provenance_digest(provenance);
  bundle.provenance.push_back(provenance);
  gpf::normalize_bundle(bundle);
  if (!gpf::seal_bundle(bundle).ok()) {
    std::fprintf(stderr, "gpf-consumer-failed seal\n");
    return 1;
  }
  if (!gpf::verify_bundle(bundle).ok()) {
    std::fprintf(stderr, "gpf-consumer-failed verify\n");
    return 1;
  }

  gpf::EffectivePolicyInput input;
  input.federation = federation;
  input.member = member;
  input.site = site;
  input.now = bundle.issued_at;
  input.runtime_version = gpf::SemanticVersion{1, 0, 0};
  // The consumer states the capability catalog generation it knows about; a bundle authored
  // against a newer catalog is deferred rather than guessed at.
  input.capability_catalog.generation = gpf::Generation{1};
  input.accepted_bundles.push_back(bundle);
  auto compiled = gpf::compile_effective_policy(input);
  if (!compiled.ok()) {
    std::fprintf(stderr, "gpf-consumer-failed compile: %s\n", compiled.error.to_string().c_str());
    return 1;
  }
  const gpf::EffectiveEntry* mandatory = compiled->find("power", "max_kw");
  if (mandatory == nullptr || !gpf::entry_state_is_binding(mandatory->state) ||
      !(mandatory->value == gpf::SettingValue::integer_value(100))) {
    std::fprintf(stderr, "gpf-consumer-failed effective-policy\n");
    return 1;
  }

  // The canonical JSON surface is part of the public API and must round-trip here too.
  auto parsed = gpf::JsonValue::parse(gpf::bundle_to_json(bundle).dump(true));
  if (!parsed.ok()) return 1;
  auto restored = gpf::bundle_from_json(*parsed);
  if (!restored.ok() || restored->integrity_digest != bundle.integrity_digest) {
    std::fprintf(stderr, "gpf-consumer-failed round-trip\n");
    return 1;
  }

  std::printf("gpf-consumer-ok version=%d.%d.%d entries=%zu digest=%s\n", gpf::kVersionMajor,
              gpf::kVersionMinor, gpf::kVersionPatch, compiled->entries.size(),
              compiled->digest.to_hex().c_str());
  return 0;
}
