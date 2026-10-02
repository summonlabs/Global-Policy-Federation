// gpf-site — an independent site policy process.
//
// The site owns its durable state, its local overrides and its effective policy. It accepts policy
// from the federation, activates it, reports receipts, and keeps working through a partition
// exactly as far as its accepted policy permits.

#include "gpf/plan.hpp"
#include "gpf/platform.hpp"
#include "gpf/runtime.hpp"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>

namespace {

using namespace gpf;

void usage() {
  std::cout <<
      "gpf-site — Global Policy Federation site agent\n"
      "\n"
      "usage:\n"
      "  gpf-site run --plan FILE --site-index N --store DIR --connect HOST:PORT\n"
      "               [--sync-count N] [--seed N] [--override DOMAIN/SUBJECT=VALUE]\n"
      "               [--override-reason TEXT] [--out FILE] [--json]\n"
      "\n"
      "exit codes: 0 synced, 2 partitioned (no federation contact), 1 failure\n";
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
  std::cerr << "gpf-site: " << message << "\n";
  return code;
}

bool parse_endpoint(const std::string& text, std::string* host, std::uint16_t* port) {
  const std::size_t colon = text.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= text.size()) return false;
  *host = text.substr(0, colon);
  const unsigned long value = std::strtoul(text.substr(colon + 1).c_str(), nullptr, 10);
  if (value == 0 || value > 65535) return false;
  *port = static_cast<std::uint16_t>(value);
  return true;
}

JsonValue summarise_effective(const EffectivePolicy& policy) {
  JsonValue by_state = JsonValue::object();
  for (const EffectiveEntry& entry : policy.entries) {
    const std::string state = entry_state_name(entry.state);
    const JsonValue* existing = by_state.find(state);
    const std::int64_t count = existing != nullptr ? existing->as_int() : 0;
    by_state.set_field(state, JsonValue::integer(count + 1));
  }
  // The decision trail behind the effective policy, bounded and newest-first per subject.
  JsonValue::Array decisions;
  for (const Receipt& receipt : policy.receipts) {
    if (decisions.size() >= 24) break;
    decisions.push_back(JsonValue::object({
        {"kind", JsonValue::text(receipt_kind_name(receipt.kind))},
        {"reason_code", JsonValue::text(receipt.reason_code)},
        {"rule", JsonValue::text(receipt.rule.to_string())},
        {"detail", JsonValue::text(receipt.detail.substr(0, 160))},
    }));
  }
  JsonValue::Array entries;
  for (const EffectiveEntry& entry : policy.entries) {
    JsonValue::Array explanation;
    for (const std::string& line : entry.explanation) explanation.push_back(JsonValue::text(line));
    entries.push_back(JsonValue::object({
        {"subject", JsonValue::text(entry.domain + "/" + entry.subject)},
        {"state", JsonValue::text(entry_state_name(entry.state))},
        {"value", setting_value_to_json(entry.value)},
        {"reason_code", JsonValue::text(entry.reason_code)},
        {"override", JsonValue::text(entry.applied_override.to_string())},
        {"explanation", JsonValue::array(std::move(explanation))},
    }));
  }
  return JsonValue::object({
      {"partitioned", JsonValue::boolean(policy.partitioned)},
      {"global_generation", JsonValue::integer(static_cast<std::int64_t>(policy.global_generation.value))},
      {"local_generation", JsonValue::integer(static_cast<std::int64_t>(policy.local_generation.value))},
      {"rules_considered", JsonValue::integer(static_cast<std::int64_t>(policy.rules_considered))},
      {"rules_applied", JsonValue::integer(static_cast<std::int64_t>(policy.rules_applied))},
      {"rules_withheld", JsonValue::integer(static_cast<std::int64_t>(policy.rules_withheld))},
      {"rules_rejected", JsonValue::integer(static_cast<std::int64_t>(policy.rules_rejected))},
      {"rules_deferred", JsonValue::integer(static_cast<std::int64_t>(policy.rules_deferred))},
      {"rules_revoked", JsonValue::integer(static_cast<std::int64_t>(policy.rules_revoked))},
      {"rules_superseded", JsonValue::integer(static_cast<std::int64_t>(policy.rules_superseded))},
      {"overrides_applied", JsonValue::integer(static_cast<std::int64_t>(policy.overrides_applied))},
      {"overrides_refused", JsonValue::integer(static_cast<std::int64_t>(policy.overrides_refused))},
      {"conflicts", JsonValue::integer(static_cast<std::int64_t>(policy.conflicts.size()))},
      {"entries_by_state", by_state},
      {"entries", JsonValue::array(std::move(entries))},
      {"decisions", JsonValue::array(std::move(decisions))},
      {"digest", JsonValue::text(policy.digest.to_hex())},
  });
}

}  // namespace

int main(int argc, char** argv) {
  net::ensure_initialized();
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string command = argv[1];
  if (command == "help" || command == "--help") {
    usage();
    return 0;
  }
  if (command != "run") {
    usage();
    return 2;
  }
  const auto options = parse_options(argc, argv, 2);
  const auto plan_option = options.find("plan");
  const auto store_option = options.find("store");
  const auto connect_option = options.find("connect");
  if (plan_option == options.end() || store_option == options.end() || connect_option == options.end()) {
    return fail("run needs --plan FILE --store DIR --connect HOST:PORT");
  }
  auto plan = load_plan(plan_option->second);
  if (!plan) return fail("cannot load plan: " + plan.error.to_string());
  const std::size_t site_index = static_cast<std::size_t>(option_u64(options, "site-index", 0));
  if (site_index >= plan->sites.size()) return fail("site index is out of range");
  const PlanSite& entry = plan->sites[site_index];

  std::string host;
  std::uint16_t port = 0;
  if (!parse_endpoint(connect_option->second, &host, &port)) {
    return fail("connect endpoint must be HOST:PORT");
  }

  SiteConfig config;
  config.federation = plan->federation;
  config.member = entry.member;
  config.site = entry.site;
  config.root_member = plan->root_member;
  config.store_directory = store_option->second;
  config.id_seed = option_u64(options, "seed", 1000 + site_index);
  config.worker_threads = 1;

  auto runtime = SiteRuntime::open(config);
  if (!runtime) return fail("cannot open the site runtime: " + runtime.error.to_string());
  (*runtime)->set_membership(plan->membership);

  // Capability declaration: what this site actually implements, expressed against the catalog
  // generation it knows. A site that declares nothing is taken at its word and is refused
  // capability-gated policy rather than silently assumed to support it.
  // The declaration is durable: an operator states capabilities once, and a restart does not
  // silently withdraw them. Omitting the flag keeps what the store already holds.
  const auto capabilities_option = options.find("capabilities");
  if (capabilities_option != options.end()) {
    SiteCapabilitySnapshot declaration;
    declaration.catalog_generation = plan->catalog.generation;
    if (capabilities_option->second != "none") {
      for (const std::string& entry_text : split_ascii(capabilities_option->second, ',')) {
        const std::size_t equals = entry_text.find('=');
        if (equals == std::string::npos) return fail("--capabilities entries must be NAME=VERSION");
        auto version = SemanticVersion::parse(entry_text.substr(equals + 1));
        if (!version) return fail("invalid capability version: " + version.error.to_string());
        declaration.capabilities.push_back(CapabilityRef{entry_text.substr(0, equals), *version});
      }
    }
    const Status declared = (*runtime)->set_capabilities(declaration);
    if (!declared.ok()) return fail("cannot declare capabilities: " + declared.error.to_string());
  }

  const bool connected = (*runtime)->connect(host, port).ok();

  std::size_t accepted_total = 0;
  std::size_t rejected_total = 0;
  std::size_t syncs = 0;
  const std::uint64_t sync_count = option_u64(options, "sync-count", 1);
  if (connected) {
    for (std::uint64_t i = 0; i < sync_count; ++i) {
      std::size_t accepted = 0;
      std::size_t rejected = 0;
      const Status status = (*runtime)->sync_once(Timestamp{platform::system_now_millis()}, &accepted,
                                                  &rejected);
      if (!status.ok()) {
        std::cerr << "gpf-site: sync failed: " << status.error.to_string() << "\n";
        break;
      }
      accepted_total += accepted;
      rejected_total += rejected;
      ++syncs;
    }
  } else {
    std::cerr << "gpf-site: federation is unreachable; continuing without new global authority\n";
  }

  // Activation: compile effective policy on the runtime's worker and record the receipts it
  // produced, so the evidence trail matches the decision that was actually made.
  std::size_t activation_receipts = 0;
  auto compiled = (*runtime)->activate(Timestamp{platform::system_now_millis()}, &activation_receipts);
  if (!compiled) return fail("compilation failed: " + compiled.error.to_string());

  std::string override_state = "none";
  const auto override_option = options.find("override");
  if (override_option != options.end()) {
    const std::size_t slash = override_option->second.find('/');
    const std::size_t equals = override_option->second.find('=');
    if (slash == std::string::npos || equals == std::string::npos || equals < slash) {
      return fail("--override must be DOMAIN/SUBJECT=VALUE");
    }
    const std::string domain = override_option->second.substr(0, slash);
    const std::string subject = override_option->second.substr(slash + 1, equals - slash - 1);
    const std::string value_text = override_option->second.substr(equals + 1);
    SettingValue value = SettingValue::unset();
    char* end = nullptr;
    const long long numeric = std::strtoll(value_text.c_str(), &end, 10);
    if (end != nullptr && *end == '\0' && !value_text.empty()) {
      value = SettingValue::integer_value(numeric);
    } else if (value_text == "true" || value_text == "false") {
      value = SettingValue::boolean_value(value_text == "true");
    } else {
      value = SettingValue::text_value(value_text);
    }

    // The override must name the delegated authority it uses when the governing rule requires one.
    const EffectiveEntry* governed = compiled->find(domain, subject);
    GrantId authority;
    if (governed != nullptr) {
      const AuthorityLedger ledger = (*runtime)->ledger();
      const AuthorityDecision decision = ledger.evaluate(
          entry.member, AuthorityAction::OverridePolicy, RuleScope::for_sites({entry.site}), domain,
          Timestamp{platform::system_now_millis()}, &plan->membership);
      if (decision.granted()) authority = decision.grant;
    }
    // Each invocation registers a distinct decision, so the identity is drawn from a stream that
    // advances with the wall clock rather than repeating the same override identity every run.
    const std::uint64_t invocation_seed =
        config.id_seed ^ 0xABCDEFull ^ static_cast<std::uint64_t>(platform::system_now_millis());
    IdGenerator ids(invocation_seed);
    auto record = make_override_for_subject(ids, *plan, entry, *compiled, domain, subject,
                                            std::move(value), authority,
                                            options.count("override-author") != 0
                                                ? options.at("override-author")
                                                : "site-operator",
                                            options.count("override-reason") != 0
                                                ? options.at("override-reason")
                                                : "local operating envelope",
                                            Timestamp{platform::system_now_millis()}, Generation{1});
    if (!record) {
      override_state = "unbound:" + record.error.message;
    } else {
      bool accepted = false;
      std::string reason;
      const Status status = (*runtime)->register_override(*record, &accepted, &reason);
      if (!status.ok()) return fail("override registration failed: " + status.error.to_string());
      override_state = accepted ? "registered" : ("refused:" + reason);
      if (accepted) {
        std::size_t override_receipts = 0;
        auto recompiled =
            (*runtime)->activate(Timestamp{platform::system_now_millis()}, &override_receipts);
        if (recompiled) {
          compiled = std::move(recompiled);
          activation_receipts += override_receipts;
          // Registration is not application: the outcome reported here is the compiler's verdict.
          const EffectiveEntry* result = compiled->find(domain, subject);
          if (result != nullptr && result->state == EntryState::Overridden) {
            override_state = "applied";
          } else if (result != nullptr) {
            override_state = "refused:" + result->reason_code;
          } else {
            override_state = "refused:no-effective-entry";
          }
        }
      } else {
        override_state = "refused:" + reason;
      }
    }
  }

  // Receipts are reported after activation, so the federation receives the evidence for the
  // decision the site actually made rather than only for the acceptance before it.
  std::size_t reported_total = 0;
  if (connected) {
    std::size_t reported = 0;
    const Status report = (*runtime)->report_receipts(Timestamp{platform::system_now_millis()}, &reported);
    if (!report.ok()) {
      std::cerr << "gpf-site: receipt report failed: " << report.error.to_string() << "\n";
    }
    reported_total = reported;
  }

  const SiteStatus status = (*runtime)->status();
  JsonValue summary = JsonValue::object({
      {"event", JsonValue::text("site-summary")},
      {"site", JsonValue::text(entry.site.to_string())},
      {"member", JsonValue::text(entry.member.to_string())},
      {"connected", JsonValue::boolean(status.connected)},
      {"partitioned", JsonValue::boolean(status.partitioned)},
      {"syncs", JsonValue::integer(static_cast<std::int64_t>(syncs))},
      {"accepted_bundles", JsonValue::integer(static_cast<std::int64_t>(status.accepted_bundles))},
      {"accepted_this_run", JsonValue::integer(static_cast<std::int64_t>(accepted_total))},
      {"rejected_this_run", JsonValue::integer(static_cast<std::int64_t>(rejected_total))},
      {"applied_global_generation",
       JsonValue::integer(static_cast<std::int64_t>(status.applied_global_generation.value))},
      {"local_generation", JsonValue::integer(static_cast<std::int64_t>(status.local_generation.value))},
      {"store_epoch", JsonValue::integer(static_cast<std::int64_t>(status.store_epoch.value))},
      {"receipts", JsonValue::integer(static_cast<std::int64_t>(status.receipts))},
      {"pending_receipts", JsonValue::integer(static_cast<std::int64_t>(status.pending_receipts))},
      {"reported_receipts", JsonValue::integer(static_cast<std::int64_t>(status.reported_receipts))},
      {"reported_this_run", JsonValue::integer(static_cast<std::int64_t>(reported_total))},
      {"overrides", JsonValue::integer(static_cast<std::int64_t>(status.overrides))},
      {"overrides_refused", JsonValue::integer(static_cast<std::int64_t>(compiled->overrides_refused))},
      {"override_state", JsonValue::text(override_state)},
      {"compilations", JsonValue::integer(static_cast<std::int64_t>(status.compilations))},
      {"stale_compilations", JsonValue::integer(static_cast<std::int64_t>(status.stale_compilations))},
      {"effective", summarise_effective(*compiled)},
  });
  const auto out = options.find("out");
  const std::string serialized = summary.dump(true);
  if (out != options.end()) {
    const Status written = platform::write_file_atomic(out->second, serialized + "\n");
    if (!written.ok()) return fail("cannot write summary: " + written.error.to_string());
  }
  std::cout << serialized << std::endl;

  const Status shutdown_status = (*runtime)->shutdown();
  if (!shutdown_status.ok()) return fail("shutdown failed: " + shutdown_status.error.to_string());
  return connected ? 0 : 2;
}
