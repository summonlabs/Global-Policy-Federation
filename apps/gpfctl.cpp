// gpfctl — offline operations for Global Policy Federation artifacts.
//
// Nothing here is privileged: every subcommand reads or writes files and reports what it found.

#include "gpf/effective.hpp"
#include "gpf/net.hpp"
#include "gpf/plan.hpp"
#include "gpf/protocol.hpp"
#include "gpf/platform.hpp"
#include "gpf/store.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>

namespace {

using namespace gpf;

void usage() {
  std::cout <<
      "gpfctl — Global Policy Federation offline tool\n"
      "\n"
      "usage:\n"
      "  gpfctl version\n"
      "  gpfctl scenario --seed N [--sites N] [--bundles N] --out FILE\n"
      "  gpfctl validate-plan FILE\n"
      "  gpfctl compile --plan FILE --site-index N --out FILE [--partitioned]\n"
      "  gpfctl verify-store DIR [--json]\n"
      "  gpfctl explain --effective FILE --domain D --subject S\n";
}

std::map<std::string, std::string> parse_options(int argc, char** argv, int start) {
  std::map<std::string, std::string> options;
  for (int i = start; i < argc; ++i) {
    std::string argument = argv[i];
    if (argument.rfind("--", 0) != 0) continue;
    const std::size_t equals = argument.find('=');
    if (equals != std::string::npos) {
      options[argument.substr(2, equals - 2)] = argument.substr(equals + 1);
      continue;
    }
    const std::string key = argument.substr(2);
    if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
      options[key] = argv[++i];
    } else {
      options[key] = "true";
    }
  }
  return options;
}

std::uint64_t option_u64(const std::map<std::string, std::string>& options, const std::string& key,
                         std::uint64_t fallback) {
  const auto found = options.find(key);
  if (found == options.end()) return fallback;
  return std::strtoull(found->second.c_str(), nullptr, 10);
}

int fail(const std::string& message, int code = 1) {
  std::cerr << "gpfctl: " << message << "\n";
  return code;
}

int command_scenario(const std::map<std::string, std::string>& options) {
  const auto out = options.find("out");
  if (out == options.end()) return fail("scenario needs --out FILE");
  const std::uint64_t seed = option_u64(options, "seed", 1);
  const std::size_t sites = static_cast<std::size_t>(option_u64(options, "sites", 2));
  const std::size_t bundles = static_cast<std::size_t>(option_u64(options, "bundles", 2));
  auto plan = generate_scenario(seed, sites, bundles);
  if (!plan) return fail("cannot generate scenario: " + plan.error.to_string());
  const Status saved = save_plan(*plan, out->second);
  if (!saved.ok()) return fail("cannot write plan: " + saved.error.to_string());
  std::cout << JsonValue::object({
                   {"event", JsonValue::text("scenario")},
                   {"seed", JsonValue::integer(static_cast<std::int64_t>(seed))},
                   {"sites", JsonValue::integer(static_cast<std::int64_t>(sites))},
                   {"bundles", JsonValue::integer(static_cast<std::int64_t>(bundles))},
                   {"federation", JsonValue::text(plan->federation.to_string())},
                   {"out", JsonValue::text(out->second)},
               }).dump(true) << "\n";
  return 0;
}

int command_validate_plan(const std::map<std::string, std::string>& options, const std::string& file) {
  (void)options;
  auto plan = load_plan(file);
  if (!plan) return fail("plan is not valid: " + plan.error.to_string());
  const Status validity = validate_plan(*plan);
  if (!validity.ok()) return fail("plan is not valid: " + validity.error.to_string());
  std::cout << JsonValue::object({
                   {"event", JsonValue::text("plan-valid")},
                   {"federation", JsonValue::text(plan->federation.to_string())},
                   {"sites", JsonValue::integer(static_cast<std::int64_t>(plan->sites.size()))},
                   {"grants", JsonValue::integer(static_cast<std::int64_t>(plan->grants.size()))},
                   {"bundles", JsonValue::integer(static_cast<std::int64_t>(plan->bundles.size()))},
                   {"catalog_generation",
                    JsonValue::integer(static_cast<std::int64_t>(plan->catalog.generation.value))},
               }).dump(true) << "\n";
  return 0;
}

int command_compile(const std::map<std::string, std::string>& options) {
  const auto plan_option = options.find("plan");
  if (plan_option == options.end()) return fail("compile needs --plan FILE");
  const std::size_t site_index = static_cast<std::size_t>(option_u64(options, "site-index", 0));
  auto plan = load_plan(plan_option->second);
  if (!plan) return fail("cannot load plan: " + plan.error.to_string());
  if (site_index >= plan->sites.size()) return fail("site index is out of range");

  const PlanSite& entry = plan->sites[site_index];
  EffectivePolicyInput input;
  input.federation = plan->federation;
  input.member = entry.member;
  input.site = entry.site;
  input.now = Timestamp{platform::system_now_millis()};
  input.accepted_bundles = plan->bundles;
  input.capability_catalog = plan->catalog;
  for (const CapabilityRef& capability : plan->catalog.capabilities) {
    input.capabilities.capabilities.push_back(capability);
  }
  input.capabilities.catalog_generation = plan->catalog.generation;
  input.membership = &plan->membership;
  input.partitioned = options.find("partitioned") != options.end();
  // The tool compiles as a runtime of its own version; an operator may state a different one.
  const auto runtime_option = options.find("runtime-version");
  auto runtime_version = runtime_option != options.end()
                             ? SemanticVersion::parse(runtime_option->second)
                             : Result<SemanticVersion>::success(
                                   SemanticVersion{kVersionMajor, kVersionMinor, kVersionPatch});
  if (!runtime_version) return fail("invalid --runtime-version: " + runtime_version.error.to_string());
  input.runtime_version = *runtime_version;
  // Offline compilation has no site runtime, so a site's own declarations are the catalog's: the
  // difference between "unsupported" and "unknown" is exercised by the runtime tests.
  AuthorityLedger ledger(plan->federation);
  ledger.set_root_member(plan->root_member);
  const Status restored = ledger.restore(plan->grants, plan->revocations, Epoch{}, input.now);
  if (!restored.ok()) return fail("cannot restore authority: " + restored.error.to_string());
  input.authority = &ledger;

  auto compiled = compile_effective_policy(input);
  if (!compiled) return fail("compilation failed: " + compiled.error.to_string());
  const JsonValue document = effective_policy_to_json(*compiled);
  const auto out = options.find("out");
  if (out == options.end()) {
    std::cout << document.dump() << "\n";
    return 0;
  }
  const Status written = platform::write_file_atomic(out->second, document.dump() + "\n");
  if (!written.ok()) return fail("cannot write compilation: " + written.error.to_string());
  std::cout << JsonValue::object({
                   {"event", JsonValue::text("compiled")},
                   {"entries", JsonValue::integer(static_cast<std::int64_t>(compiled->entries.size()))},
                   {"conflicts", JsonValue::integer(static_cast<std::int64_t>(compiled->conflicts.size()))},
                   {"receipts", JsonValue::integer(static_cast<std::int64_t>(compiled->receipts.size()))},
                   {"digest", JsonValue::text(compiled->digest.to_hex())},
                   {"out", JsonValue::text(out->second)},
               }).dump(true) << "\n";
  return 0;
}

int command_verify_store(const std::map<std::string, std::string>& options, const std::string& directory) {
  StoreOpenOptions open_options;
  open_options.directory = directory;
  open_options.create_if_missing = false;
  auto store = DurableStore::open(open_options);
  if (!store) return fail("cannot open store: " + store.error.to_string());
  const RecoveryReport& report = store->recovery();
  JsonValue summary = JsonValue::object({
      {"event", JsonValue::text("store")},
      {"store_id", JsonValue::text(store->identity().id.to_string())},
      {"federation", JsonValue::text(store->identity().federation.to_string())},
      {"member", JsonValue::text(store->identity().member.to_string())},
      {"site", JsonValue::text(store->identity().site.to_string())},
      {"recovery", JsonValue::text(recovery_outcome_name(report.outcome))},
      {"records_replayed", JsonValue::integer(static_cast<std::int64_t>(report.records_replayed))},
      {"bytes_discarded", JsonValue::integer(static_cast<std::int64_t>(report.bytes_discarded))},
      {"epoch", JsonValue::integer(static_cast<std::int64_t>(report.opened_epoch.value))},
      {"last_sequence", JsonValue::integer(static_cast<std::int64_t>(report.last_sequence.value))},
      {"writable", JsonValue::boolean(report.writable)},
      {"detail", JsonValue::text(report.detail)},
  });
  JsonValue::Array notes;
  for (const std::string& note : report.notes) notes.push_back(JsonValue::text(note));
  summary.set_field("notes", JsonValue::array(std::move(notes)));
  auto state = replay_records(store->identity(), store->records());
  if (state) {
    summary.set_field("accepted_bundles", JsonValue::integer(static_cast<std::int64_t>(state->accepted_bundles.size())));
    summary.set_field("overrides", JsonValue::integer(static_cast<std::int64_t>(state->overrides.size())));
    summary.set_field("receipts", JsonValue::integer(static_cast<std::int64_t>(state->receipts.size())));
    summary.set_field("applied_sequence", JsonValue::integer(static_cast<std::int64_t>(state->applied_sequence.value)));
    // Which local overrides this site holds, and the exact rule and generation each one is bound
    // to. This is the question an operator asks first when an override is not taking effect.
    JsonValue::Array held_overrides;
    for (const LocalOverride& record : state->overrides) {
      held_overrides.push_back(JsonValue::object({
          {"id", JsonValue::text(record.id.to_string())},
          {"subject", JsonValue::text(record.key())},
          {"target_rule", JsonValue::text(record.target_rule.to_string())},
          {"target_bundle", JsonValue::text(record.target_bundle.to_string())},
          {"target_generation",
           JsonValue::integer(static_cast<std::int64_t>(record.target_bundle_generation.value))},
          {"value", setting_value_to_json(record.value)},
          {"reason", JsonValue::text(record.reason.substr(0, 96))},
      }));
    }
    summary.set_field("held_overrides", JsonValue::array(std::move(held_overrides)));
    JsonValue::Array recent_receipts;
    const std::size_t first = state->receipts.size() > 12 ? state->receipts.size() - 12 : 0;
    for (std::size_t i = first; i < state->receipts.size(); ++i) {
      const Receipt& receipt = state->receipts[i];
      recent_receipts.push_back(JsonValue::object({
          {"kind", JsonValue::text(receipt_kind_name(receipt.kind))},
          {"reason_code", JsonValue::text(receipt.reason_code)},
          {"rule", JsonValue::text(receipt.rule.to_string())},
          {"override", JsonValue::text(receipt.override_id.to_string())},
          {"detail", JsonValue::text(receipt.detail.substr(0, 120))},
      }));
    }
    summary.set_field("recent_receipts", JsonValue::array(std::move(recent_receipts)));
  } else {
    summary.set_field("replay_error", JsonValue::text(state.error.to_string()));
  }
  const auto out = options.find("out");
  if (out != options.end()) {
    const Status written = platform::write_file_atomic(out->second, summary.dump(true) + "\n");
    if (!written.ok()) return fail("cannot write store report: " + written.error.to_string());
  }
  std::cout << summary.dump(true) << "\n";
  return report.writable ? 0 : 3;
}

int command_explain(const std::map<std::string, std::string>& options) {
  const auto effective = options.find("effective");
  const auto domain = options.find("domain");
  const auto subject = options.find("subject");
  if (effective == options.end() || domain == options.end() || subject == options.end()) {
    return fail("explain needs --effective FILE --domain D --subject S");
  }
  auto text = platform::read_file(effective->second, limits::kMaxJsonDocumentBytes);
  if (!text) return fail("cannot read effective policy: " + text.error.to_string());
  auto parsed = JsonValue::parse(*text);
  if (!parsed) return fail("cannot parse effective policy: " + parsed.error.to_string());
  auto policy = effective_policy_from_json(*parsed);
  if (!policy) return fail("effective policy is not valid: " + policy.error.to_string());
  const EffectiveEntry entry = explain_subject(*policy, domain->second, subject->second);
  JsonValue::Array explanation;
  for (const std::string& line : entry.explanation) explanation.push_back(JsonValue::text(line));
  std::cout << JsonValue::object({
                   {"domain", JsonValue::text(entry.domain)},
                   {"subject", JsonValue::text(entry.subject)},
                   {"state", JsonValue::text(entry_state_name(entry.state))},
                   {"binding", JsonValue::boolean(entry_state_is_binding(entry.state))},
                   {"value", setting_value_to_json(entry.value)},
                   {"class", JsonValue::text(rule_class_name(entry.effective_class))},
                   {"source_rule", JsonValue::text(entry.source_rule.to_string())},
                   {"source_bundle", JsonValue::text(entry.source_bundle.to_string())},
                   {"reason_code", JsonValue::text(entry.reason_code)},
                   {"detail", JsonValue::text(entry.detail)},
                   {"explanation", JsonValue::array(std::move(explanation))},
               }).dump(true) << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  net::ensure_initialized();
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string command = argv[1];
  if (command == "version" || command == "--version") {
    std::cout << "gpfctl " << kVersionMajor << "." << kVersionMinor << "." << kVersionPatch
              << " (protocol " << kProtocolVersion << ")\n";
    return 0;
  }
  if (command == "help" || command == "--help") {
    usage();
    return 0;
  }
  const auto options = parse_options(argc, argv, 2);
  if (command == "scenario") return command_scenario(options);
  if (command == "validate-plan") {
    if (argc < 3) return fail("validate-plan needs a file");
    return command_validate_plan(options, argv[2]);
  }
  if (command == "compile") return command_compile(options);
  if (command == "verify-store") {
    if (argc < 3) return fail("verify-store needs a directory");
    return command_verify_store(options, argv[2]);
  }
  if (command == "explain") return command_explain(options);
  usage();
  return 2;
}
