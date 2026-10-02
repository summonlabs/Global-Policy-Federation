// Global Policy Federation — benchmarks.
//
// Every number printed here was measured on the machine that ran the binary. Nothing is
// extrapolated, modeled, or estimated, and no before/after comparison is published unless both
// sides were measured in the same run. Each result is labelled:
//
//   REAL    measured end to end in this process on this host
//   DURABLE measured including the platform flush, so it is a durability cost, not CPU cost

#include "gpf/effective.hpp"
#include "gpf/plan.hpp"
#include "gpf/platform.hpp"
#include "gpf/protocol.hpp"
#include "gpf/store.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

using namespace gpf;
using Clock = std::chrono::steady_clock;

namespace {

struct Measurement {
  std::string name;
  std::string label;
  std::size_t iterations{0};
  double mean_us{0.0};
  double median_us{0.0};
  double p95_us{0.0};
  double min_us{0.0};
  double ops_per_second{0.0};
  std::string notes;
};

std::string json_escape_simple(const std::string& text) { return json_escape(text); }

template <class Operation>
Measurement measure(const std::string& name, const std::string& label, std::size_t iterations,
                    Operation operation, const std::string& notes = {}) {
  std::vector<double> samples;
  samples.reserve(iterations);
  // Warm-up is untimed so the first allocation and page faults do not distort the sample set.
  operation();
  for (std::size_t i = 0; i < iterations; ++i) {
    const Clock::time_point start = Clock::now();
    operation();
    const Clock::time_point end = Clock::now();
    samples.push_back(std::chrono::duration<double, std::micro>(end - start).count());
  }
  std::sort(samples.begin(), samples.end());
  Measurement result;
  result.name = name;
  result.label = label;
  result.iterations = iterations;
  result.min_us = samples.front();
  result.median_us = samples[samples.size() / 2];
  result.p95_us = samples[static_cast<std::size_t>(static_cast<double>(samples.size()) * 0.95)];
  double total = 0.0;
  for (double sample : samples) total += sample;
  result.mean_us = total / static_cast<double>(samples.size());
  result.ops_per_second = result.mean_us > 0.0 ? 1000000.0 / result.mean_us : 0.0;
  result.notes = notes;
  return result;
}

void report(const Measurement& measurement) {
  // json_escape already returns a quoted string, so it is inserted without extra quotes.
  std::printf(
      "{\"benchmark\":%s,\"evidence\":\"%s\",\"iterations\":%zu,\"mean_us\":%.3f,"
      "\"median_us\":%.3f,\"p95_us\":%.3f,\"min_us\":%.3f,\"operations_per_second\":%.1f,"
      "\"notes\":%s}\n",
      json_escape_simple(measurement.name).c_str(), measurement.label.c_str(), measurement.iterations,
      measurement.mean_us, measurement.median_us, measurement.p95_us, measurement.min_us,
      measurement.ops_per_second, json_escape_simple(measurement.notes).c_str());
  std::fflush(stdout);
}

// Builds a synthetic multi-site policy set with distinct subjects per publisher so the set is
// valid rather than internally contradictory.
std::vector<PolicyBundle> synthetic_bundles(IdGenerator& ids, FederationId federation,
                                            std::size_t publishers, std::size_t bundles_each,
                                            std::size_t rules_each, Timestamp now) {
  std::vector<PolicyBundle> bundles;
  for (std::size_t publisher = 0; publisher < publishers; ++publisher) {
    MemberId issuer;
    issuer.value = ids.next();
    for (std::size_t index = 0; index < bundles_each; ++index) {
      std::vector<Rule> rules;
      for (std::size_t rule_index = 0; rule_index < rules_each; ++rule_index) {
        Rule rule;
        rule.id.value = ids.next();
        rule.version = SemanticVersion{1, 0, 0};
        rule.domain = "domain" + std::to_string(rule_index % 8);
        rule.subject = "subject_" + std::to_string(publisher) + "_" + std::to_string(rule_index);
        rule.rule_class = rule_index % 3 == 0 ? RuleClass::Mandatory : RuleClass::Default;
        rule.precedence = rule.rule_class == RuleClass::Mandatory ? 1u : 0u;
        rule.scope = RuleScope::federation();
        rule.value = SettingValue::integer_value(static_cast<std::int64_t>(rule_index));
        if (rule.rule_class == RuleClass::Mandatory) {
          rule.override_permission = index == 0 ? OverridePermission::Allowed
                                                : OverridePermission::AllowedWithAuthority;
        }
        rules.push_back(std::move(rule));
      }
      PolicyBundle bundle;
      bundle.id.value = ids.next();
      bundle.federation = federation;
      bundle.global_generation = Generation{index + 1};
      bundle.issuer_member = issuer;
      bundle.scope = RuleScope::federation();
      bundle.issued_at = now;
      bundle.effective_from = now;
      bundle.required_runtime = SemanticVersion{1, 0, 0};
      bundle.capability_catalog_generation = Generation{1};
      bundle.staleness = StalenessPolicy::require_fresh();
      bundle.rules = std::move(rules);
      ProvenanceEntry entry;
      entry.actor = "benchmark";
      entry.member = issuer;
      entry.generation = bundle.global_generation;
      entry.at = now;
      entry.note = "benchmark publication";
      entry.entry_digest = *compute_provenance_digest(entry);
      bundle.provenance.push_back(entry);
      normalize_bundle(bundle);
      (void)seal_bundle(bundle);
      bundles.push_back(std::move(bundle));
    }
  }
  return bundles;
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t scale = 1;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument.rfind("--scale=", 0) == 0) {
      scale = static_cast<std::size_t>(std::strtoull(argument.c_str() + 8, nullptr, 10));
      if (scale == 0) scale = 1;
    }
  }

  const Timestamp now{platform::system_now_millis()};
  IdGenerator ids(20260101);
  FederationId federation;
  federation.value = ids.next();
  MemberId member;
  member.value = ids.next();
  SiteId site;
  site.value = ids.next();

  const std::size_t publishers = 4 * scale;
  const std::size_t bundles_each = 8 * scale;
  const std::size_t rules_each = 64 * scale;
  std::vector<PolicyBundle> bundles =
      synthetic_bundles(ids, federation, publishers, bundles_each, rules_each, now);
  std::size_t total_rules = 0;
  for (const PolicyBundle& bundle : bundles) total_rules += bundle.rules.size();

  std::printf(
      "{\"benchmark\":\"workload\",\"evidence\":\"REAL\",\"publishers\":%zu,\"bundles\":%zu,"
      "\"rules_per_bundle\":%zu,\"total_rules\":%zu,\"note\":\"synthetic multi-site policy set generated in process\"}\n",
      publishers, bundles.size(), rules_each, total_rules);
  std::fflush(stdout);

  // ---- Canonical sealing and verification -------------------------------------------------
  {
    PolicyBundle target = bundles.front();
    report(measure("bundle.seal", "REAL", 200, [&] {
      PolicyBundle copy = target;
      (void)seal_bundle(copy);
    }, "canonical encoding and SHA-256 over " + std::to_string(rules_each) + " rules"));
  }
  {
    const PolicyBundle& target = bundles.front();
    report(measure("bundle.verify", "REAL", 200, [&] { (void)verify_bundle(target); },
                   "integrity and compatibility digest verification"));
  }

  // ---- Effective policy compilation -------------------------------------------------------
  {
    EffectivePolicyInput input;
    input.federation = federation;
    input.member = member;
    input.site = site;
    input.now = now;
    input.accepted_bundles = bundles;
    input.runtime_version = SemanticVersion{1, 0, 0};
    auto compiled = compile_effective_policy(input);
    if (!compiled.ok()) {
      std::fprintf(stderr, "compilation failed: %s\n", compiled.error.to_string().c_str());
      return 1;
    }
    std::printf(
        "{\"benchmark\":\"compile.result\",\"evidence\":\"REAL\",\"entries\":%zu,\"conflicts\":%zu,"
        "\"rules_considered\":%zu,\"conflicts_contained\":%zu}\n",
        compiled->entries.size(), compiled->conflicts.size(), compiled->rules_considered,
        compiled->conflicts.size());
    std::fflush(stdout);
    report(measure("effective.compile", "REAL", 50,
                   [&] { (void)compile_effective_policy(input); },
                   "full compile of the synthetic set for one site, verifying every bundle"));
    EffectivePolicyInput trusted = input;
    trusted.verify_bundle_integrity = false;
    report(measure("effective.compile_preverified", "REAL", 50,
                   [&] { (void)compile_effective_policy(trusted); },
                   "same compile with bundles already verified at acceptance"));
  }
  {
    // Reconciliation-shaped work: the same compile path with older generations present, which is
    // what a site does after reconnecting.
    EffectivePolicyInput input;
    input.federation = federation;
    input.member = member;
    input.site = site;
    input.now = now;
    input.accepted_bundles = bundles;
    input.runtime_version = SemanticVersion{1, 0, 0};
    input.partitioned = true;
    input.last_contact_at = Timestamp{now.ms - 1000};
    report(measure("effective.compile_partitioned", "REAL", 25,
                   [&] { (void)compile_effective_policy(input); },
                   "compile while the federation is unreachable"));
  }

  // ---- Canonical serialization ------------------------------------------------------------
  {
    const std::string dumped = bundle_to_json(bundles.front()).dump(true);
    report(measure("bundle.json.encode", "REAL", 500,
                   [&] { (void)bundle_to_json(bundles.front()).dump(true); },
                   "canonical JSON of one bundle (" + std::to_string(dumped.size()) + " bytes)"));
    report(measure("bundle.json.decode", "REAL", 500,
                   [&] { (void)bundle_from_json(*JsonValue::parse(dumped)); },
                   "parse and validate one bundle document"));
  }

  // ---- Wire protocol ---------------------------------------------------------------
  {
    SyncResponseMessage response;
    response.bundles = bundles;
    Envelope envelope = make_envelope(MessageType::SyncResponse, SequenceNumber{1},
                                      sync_response_to_json(response));
    const std::string frame = encode_frame(envelope);
    report(measure("protocol.encode", "REAL", 200, [&] { (void)encode_frame(envelope); },
                   "frame of " + std::to_string(frame.size()) + " bytes"));
    report(measure("protocol.decode", "REAL", 200, [&] { (void)decode_frame(frame); },
                   "decode and validate the same frame"));
    report(measure("protocol.roundtrip", "REAL", 200, [&] {
                     auto decoded = decode_frame(frame);
                     if (decoded) (void)sync_response_from_json(decoded->body);
                   },
                   "frame decode plus message body validation"));
  }

  // ---- Durable store ----------------------------------------------------------------------
  {
    const std::filesystem::path directory =
        std::filesystem::temp_directory_path() / ("gpf-bench-store-" + std::to_string(now.ms));
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    StoreOpenOptions options;
    options.directory = directory;
    options.identity.federation = federation;
    options.identity.member = member;
    options.identity.site = site;
    options.identity.created_at = now;
    auto store = DurableStore::open(options);
    if (!store.ok()) {
      std::fprintf(stderr, "store open failed: %s\n", store.error.to_string().c_str());
      return 1;
    }
    const std::size_t appends = 200;
    std::size_t written = 0;
    report(measure("store.append", "DURABLE", appends, [&] {
             const Status status = store->append(StoreRecordKind::SiteDescriptor,
                                                 "{\"benchmark\":\"record\"}", now);
             if (status.ok()) ++written;
           },
                   "one record per iteration, flushed to stable storage before returning"));
    store->close();
    auto reopened = DurableStore::open(options);
    if (!reopened.ok()) {
      std::fprintf(stderr, "store reopen failed: %s\n", reopened.error.to_string().c_str());
      return 1;
    }
    report(measure("store.replay", "REAL", 20, [&] { (void)reopened->records(); },
                   "replay of " + std::to_string(reopened->records().size()) + " records"));
    report(measure("store.open_recovery", "REAL", 20,
                   [&] {
                     auto again = DurableStore::open(options);
                     if (again.ok()) (void)again->close();
                   },
                   "full open, recovery classification and epoch fencing"));
    reopened->close();
    std::filesystem::remove_all(directory, error);
  }

  std::printf("{\"benchmark\":\"complete\",\"evidence\":\"REAL\",\"scale\":%zu}\n", scale);
  return 0;
}
