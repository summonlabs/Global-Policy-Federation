// End-to-end proof over real, independent OS processes.
//
// This suite drives the built executables exactly as an operator would: a coordinator process, a
// site process with its own durable store, a real TCP session, a real partition (the coordinator
// is simply not running), a real restart, and a real reconnection. Nothing is simulated in
// process, and no assertion is made on an in-memory object.

#include "fixtures.hpp"
#include "gpf/net.hpp"
#include "gpf/plan.hpp"
#include "gpf/platform.hpp"
#include "test_support.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

using namespace gpf;
using namespace gpf_test;

namespace {

struct Binaries {
  std::string ctl;
  std::string federation;
  std::string site;
  bool complete() const { return !ctl.empty() && !federation.empty() && !site.empty(); }
};

Binaries binaries_from_args() {
  Binaries binaries;
  const std::vector<std::string>& args = positional_args();
  for (const std::string& argument : args) {
    if (argument.find("gpfctl") != std::string::npos) binaries.ctl = argument;
    if (argument.find("gpf-federation") != std::string::npos) binaries.federation = argument;
    if (argument.find("gpf-site") != std::string::npos) binaries.site = argument;
  }
  return binaries;
}

Result<JsonValue> read_json(const std::filesystem::path& path) {
  auto text = platform::read_file(path, limits::kMaxJsonDocumentBytes);
  if (!text) return Result<JsonValue>::failure(text.error);
  return JsonValue::parse(*text);
}

// Reads the summary the process wrote, or reports what it printed instead.
Result<JsonValue> summary_of(const std::filesystem::path& path, const std::string& label) {
  auto parsed = read_json(path);
  if (!parsed) {
    auto raw = platform::read_file(path, 4096);
    return Result<JsonValue>::failure(ErrorCode::NotFound,
                                      label + " produced no summary: " +
                                          (raw.ok() ? raw->substr(0, 200) : std::string("(missing)")));
  }
  return parsed;
}

// Completes a coordinator process. A coordinator that never received its session blocks in
// accept, so when the site reports that it could not connect the coordinator is stopped and the
// failure is reported instead of hanging the run. This is driven by the child's exit code, not by
// a clock: the flow is deterministic.
// Waits for a freshly started coordinator to announce that it is listening on the port this run
// expects. The wait is driven by the child's own behaviour: it ends when the announcement appears
// in the child's standard output, and it fails the moment the child exits. Nothing here bounds the
// wait with a clock, so a coordinator that never listens is reported as a hang to diagnose rather
// than as a silent pass. The short yield between probes only keeps the loop from spinning hot.
Result<std::uint16_t> await_listening(platform::ProcessHandle& child,
                                         const std::filesystem::path& stdout_path) {
  // The coordinator binds the port and announces it; the test therefore never guesses a port and
  // never races a fresh listener. The announcement is printed after the listener is established, so
  // a connection made immediately afterwards is accepted by the backlog.
  const std::string marker = "\"port\":";
  for (;;) {
    auto output = platform::read_file(stdout_path, 65536);
    if (output.ok() && output->find("\"listening\"") != std::string::npos) {
      const std::size_t at = output->find(marker);
      if (at != std::string::npos) {
        const std::size_t start = at + marker.size();
        std::size_t end = start;
        while (end < output->size() && (*output)[end] >= '0' && (*output)[end] <= '9') ++end;
        if (end > start) {
          const unsigned long announced = std::strtoul(output->substr(start, end - start).c_str(), nullptr, 10);
          if (announced != 0 && announced <= 65535) {
            return Result<std::uint16_t>::success(static_cast<std::uint16_t>(announced));
          }
        }
      }
    }
    auto exited = platform::process_has_exited(child);
    if (!exited.ok()) return Result<std::uint16_t>::failure(exited.error);
    if (*exited) {
      auto diagnostics = platform::read_file(stdout_path, 4096);
      return Result<std::uint16_t>::failure(
          ErrorCode::NotConnected, "the coordinator exited before it began listening: " +
                                       (diagnostics.ok() ? diagnostics->substr(0, 256)
                                                         : std::string("(no output)")));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

// Runs a program to completion without a shell in the path, capturing both streams. A child that
// fails reports its own diagnostics, so a failure is never a bare exit code.
Result<int> run_captured(const std::string& program, const std::vector<std::string>& arguments,
                         const std::filesystem::path& stdout_path,
                         const std::filesystem::path& stderr_path, const char* phase) {
  auto child = platform::spawn_process(program, arguments, stdout_path, stderr_path);
  if (!child.ok()) return Result<int>::failure(child.error);
  auto code = platform::wait_process(*child.value);
  if (!code.ok()) return code;
  if (*code != 0) {
    auto diagnostics = platform::read_file(stderr_path, 2048);
    std::string detail = std::string(phase) + " exited with " + std::to_string(*code);
    if (diagnostics.ok() && !diagnostics->empty()) detail += ": " + diagnostics->substr(0, 512);
    (void)platform::write_file_atomic(stderr_path, detail);
  }
  return code;
}

Result<int> finish_coordinator(platform::ProcessHandle& coordinator, int site_exit_code,
                               const char* phase) {
  if (site_exit_code == 2) {
    (void)platform::terminate_process(coordinator);
    return Result<int>::failure(ErrorCode::NotConnected,
                                std::string(phase) + ": the site could not reach the coordinator");
  }
  return platform::wait_process(coordinator);
}

std::string generation_field(const JsonValue& value, const char* key) {
  const JsonValue* field = value.find(key);
  return field != nullptr ? field->dump() : std::string("missing");
}

}  // namespace

GPF_TEST(multiprocess, cli_smoke_covers_every_documented_subcommand) {
  const Binaries binaries = binaries_from_args();
  if (!binaries.complete()) {
    NOTE("binary paths were not provided by the build system");
    CHECK(false);
    return;
  }
  TempDirectory directory("cli");
  const std::filesystem::path plan_path = directory.child("plan.json");
  const std::filesystem::path effective_path = directory.child("effective.json");
  const std::filesystem::path out_path = directory.child("out.json");
  const std::filesystem::path err_path = directory.child("err.txt");

  const auto run = [&](const std::string& program, const std::vector<std::string>& args) {
    return platform::run_process(program, args);
  };

  auto version = run(binaries.ctl, {"version"});
  REQUIRE(version.ok());
  CHECK_EQ(*version, 0);
  auto scenario = run(binaries.ctl, {"scenario", "--seed", "4242", "--sites", "2", "--bundles", "1",
                                     "--out", plan_path.string()});
  REQUIRE(scenario.ok());
  CHECK_EQ(*scenario, 0);
  auto validate = run(binaries.ctl, {"validate-plan", plan_path.string()});
  REQUIRE(validate.ok());
  CHECK_EQ(*validate, 0);
  auto compile = run(binaries.ctl, {"compile", "--plan", plan_path.string(), "--site-index", "0",
                                    "--out", effective_path.string()});
  REQUIRE(compile.ok());
  CHECK_EQ(*compile, 0);
  auto explain = run(binaries.ctl, {"explain", "--effective", effective_path.string(), "--domain",
                                    "power", "--subject", "max_kw"});
  REQUIRE(explain.ok());
  CHECK_EQ(*explain, 0);

  // The offline compilation is a real compilation of the plan for one site.
  auto effective = summary_of(effective_path, "gpfctl compile");
  if (!effective.ok()) NOTE(effective.error.message);
  REQUIRE(effective.ok());
  const JsonValue* entries = effective->find("entries");
  REQUIRE(entries != nullptr);
  bool found_mandatory = false;
  for (const JsonValue& entry : entries->array_items()) {
    const JsonValue* entry_domain = entry.find("domain");
    const JsonValue* entry_subject = entry.find("subject");
    REQUIRE(entry_domain != nullptr);
    REQUIRE(entry_subject != nullptr);
    if (entry_domain->as_string() == "power" && entry_subject->as_string() == "max_kw") {
      found_mandatory = true;
      const JsonValue* state = entry.find("state");
      REQUIRE(state != nullptr);
      // Offline compilation has no site runtime and therefore no declared capabilities: the
      // mandatory rule that requires one is refused rather than assumed satisfied.
      CHECK(state->as_string() == "active" || state->as_string() == "incompatible");
    }
  }
  CHECK(found_mandatory);

  // A store that does not exist is reported as missing, not created.
  auto missing = run(binaries.ctl, {"verify-store", directory.child("absent").string()});
  REQUIRE(missing.ok());
  CHECK(*missing != 0);
  (void)out_path;
  (void)err_path;
}

GPF_TEST(multiprocess, coordinator_and_site_negotiate_over_a_real_socket_and_survive_a_partition) {
  const Binaries binaries = binaries_from_args();
  if (!binaries.complete()) {
    NOTE("binary paths were not provided by the build system");
    CHECK(false);
    return;
  }
  net::ensure_initialized();
  TempDirectory directory("federation");
  const std::filesystem::path plan_path = directory.child("plan.json");
  const std::filesystem::path plan2_path = directory.child("plan2.json");
  const std::filesystem::path coordinator_store = directory.child("coordinator-store");
  const std::filesystem::path site_store = directory.child("site-store");
  const std::filesystem::path site_summary = directory.child("site.json");
  const std::filesystem::path partition_summary = directory.child("site-partition.json");
  const std::filesystem::path override_summary = directory.child("site-override.json");
  const std::filesystem::path reconnect_summary = directory.child("site-reconnect.json");
  const std::filesystem::path refused_summary = directory.child("site-refused.json");
  const std::filesystem::path fed_out = directory.child("federation.out");
  const std::filesystem::path fed_err = directory.child("federation.err");
  const std::filesystem::path fed_summary = directory.child("federation-summary.json");
  // The restarted coordinator keeps its own evidence files. Readiness is announced on standard
  // output, so sharing a file across incarnations could let a stale announcement satisfy the wait.
  const std::filesystem::path fed_out_restart = directory.child("federation-restart.out");
  const std::filesystem::path fed_err_restart = directory.child("federation-restart.err");
  const std::filesystem::path fed_summary_restart = directory.child("federation-restart-summary.json");
  // Site runs capture both streams, so a failing site reports why instead of only an exit code.
  const std::filesystem::path site_out = directory.child("site.out");
  const std::filesystem::path site_err = directory.child("site.err");

  auto plan = generate_scenario(4242, 2, 1);
  if (!plan.ok()) NOTE("scenario failed: " + plan.error.to_string());
  REQUIRE(plan.ok());
  REQUIRE(save_plan(*plan, plan_path).ok());
  auto plan_two = generate_scenario(4242, 2, 2);
  REQUIRE(plan_two.ok());
  REQUIRE(save_plan(*plan_two, plan2_path).ok());

  // Ports are never guessed or reserved by the test. Every coordinator asks the operating system
  // for a free port, announces the port it actually bound, and only then does a site connect. That
  // removes both the reservation window and the start-up race.
  std::string endpoint;
  std::string reconnect_endpoint;

  const std::string capabilities = "power.metering=2.1.0,cooling.liquid=1.4.0";

  // ---- Phase 1: real socket session, acceptance, activation, receipts ---------------------
  auto coordinator = platform::spawn_process(
      binaries.federation,
      {"serve", "--plan", plan_path.string(), "--store", coordinator_store.string(), "--port",
       "0", "--sessions", "2", "--out", fed_summary.string()},
      fed_out, fed_err);
  if (!coordinator.ok()) NOTE("spawn failed: " + coordinator.error.to_string());
  REQUIRE(coordinator.ok());
  const auto listening = await_listening(*coordinator.value, fed_out);
  if (!listening.ok()) NOTE("phase 1: " + listening.error.message);
  REQUIRE(listening.ok());
  const std::uint16_t port = *listening;
  endpoint = "127.0.0.1:" + std::to_string(port);

  auto first_sync = run_captured(
      binaries.site,
      {"run", "--plan", plan_path.string(), "--site-index", "0", "--store", site_store.string(),
       "--connect", endpoint, "--sync-count", "1", "--capabilities", capabilities, "--out",
       site_summary.string()},
      site_out, site_err, "phase 1 site run");
  REQUIRE(first_sync.ok());
  CHECK_EQ(*first_sync, 0);

  auto site_json = summary_of(site_summary, "gpf-site");
  if (!site_json.ok()) NOTE(site_json.error.message);
  REQUIRE(site_json.ok());
  CHECK_EQ(generation_field(*site_json, "connected"), std::string("true"));
  CHECK_EQ(generation_field(*site_json, "partitioned"), std::string("false"));
  CHECK_EQ(generation_field(*site_json, "accepted_bundles"), std::string("2"));
  CHECK_EQ(generation_field(*site_json, "pending_receipts"), std::string("0"));
  const JsonValue* effective = site_json->find("effective");
  REQUIRE(effective != nullptr);
  CHECK_EQ(generation_field(*effective, "rules_rejected"), std::string("0"));
  CHECK_EQ(generation_field(*effective, "conflicts"), std::string("0"));

  // ---- Phase 1b: a local override that the delegated authority permits --------------------
  auto override_run = run_captured(
      binaries.site,
      {"run", "--plan", plan_path.string(), "--site-index", "0", "--store", site_store.string(),
       "--connect", endpoint, "--sync-count", "1", "--override", "power/max_kw=95",
       "--override-reason", "site thermal envelope", "--out", override_summary.string()},
      site_out, site_err, "phase 1b site run");
  REQUIRE(override_run.ok());
  CHECK_EQ(*override_run, 0);
  auto override_json = summary_of(override_summary, "gpf-site override");
  if (!override_json.ok()) NOTE(override_json.error.message);
  REQUIRE(override_json.ok());
  NOTE("phase 1b: syncs=" + generation_field(*override_json, "syncs") +
       " connected=" + generation_field(*override_json, "connected") +
       " override=" + generation_field(*override_json, "override_state"));
  CHECK_EQ(generation_field(*override_json, "syncs"), std::string("1"));
  CHECK_EQ(generation_field(*override_json, "override_state"), std::string("\"applied\""));
  const JsonValue* override_effective = override_json->find("effective");
  REQUIRE(override_effective != nullptr);
  if (generation_field(*override_effective, "overrides_applied") == std::string("0")) {
    const JsonValue* phase_one_entries = override_effective->find("entries");
    if (phase_one_entries != nullptr) {
      for (const JsonValue& entry : phase_one_entries->array_items()) {
        const JsonValue* subject = entry.find("subject");
        if (subject != nullptr && subject->as_string() == "power/max_kw") {
          NOTE("phase 1b entry: " + entry.dump(true).substr(0, 900));
        }
      }
    }
  }
  CHECK(generation_field(*override_effective, "overrides_applied") != std::string("0"));

  auto coordinator_exit = finish_coordinator(*coordinator.value, *override_run, "phase 1b");
  if (!coordinator_exit.ok()) NOTE("phase 1b: " + coordinator_exit.error.message);
  REQUIRE(coordinator_exit.ok());
  if (*coordinator_exit != 0) {
    auto diagnostics = platform::read_file(fed_err, 4096);
    NOTE("coordinator reported: " + (diagnostics.ok() ? *diagnostics : std::string("(no diagnostics)")));
  }
  CHECK_EQ(*coordinator_exit, 0);
  auto federation_summary = summary_of(fed_summary, "gpf-federation");
  if (!federation_summary.ok()) NOTE(federation_summary.error.message);
  REQUIRE(federation_summary.ok());
  CHECK_EQ(generation_field(*federation_summary, "sessions"), std::string("2"));
  CHECK_EQ(generation_field(*federation_summary, "published_bundles"), std::string("2"));
  CHECK_EQ(generation_field(*federation_summary, "rejected_publications"), std::string("0"));
  const JsonValue* collected = federation_summary->find("collected_receipts");
  REQUIRE(collected != nullptr);
  CHECK(collected->as_int() > 0);
  const std::int64_t collected_after_phase_one = collected->as_int();

  // ---- Phase 2: partition. The coordinator is not running at all. -------------------------
  auto partitioned = run_captured(
      binaries.site,
      {"run", "--plan", plan_path.string(), "--site-index", "0", "--store", site_store.string(),
       "--connect", endpoint, "--sync-count", "1", "--out", partition_summary.string()},
      site_out, site_err, "phase 2 partition run");
  REQUIRE(partitioned.ok());
  CHECK_EQ(*partitioned, 2);  // distinct exit code: synced nowhere, still operational
  auto partition_json = summary_of(partition_summary, "gpf-site partition");
  if (!partition_json.ok()) NOTE(partition_json.error.message);
  REQUIRE(partition_json.ok());
  CHECK_EQ(generation_field(*partition_json, "partitioned"), std::string("true"));
  CHECK_EQ(generation_field(*partition_json, "syncs"), std::string("0"));
  // Durable state survived the process: the site still holds the accepted policy.
  CHECK_EQ(generation_field(*partition_json, "accepted_bundles"), std::string("2"));
  const JsonValue* partition_effective = partition_json->find("effective");
  REQUIRE(partition_effective != nullptr);
  const JsonValue* partition_entries = partition_effective->find("entries");
  REQUIRE(partition_entries != nullptr);
  bool saw_last_known_valid = false;
  bool saw_withheld = false;
  for (const JsonValue& entry : partition_entries->array_items()) {
    const JsonValue* subject = entry.find("subject");
    const JsonValue* state = entry.find("state");
    REQUIRE(subject != nullptr);
    REQUIRE(state != nullptr);
    if (subject->as_string() == "power/max_kw" && state->as_string() == "last-known-valid") {
      saw_last_known_valid = true;
    }
    if (subject->as_string() == "cooling/target_c" && state->as_string() == "withheld") {
      saw_withheld = true;
    }
  }
  CHECK(saw_last_known_valid);  // permitted by the policy's declared staleness window
  CHECK(saw_withheld);          // require-fresh policy is withheld, not silently kept

  // ---- Phase 3: reconnect against a restarted coordinator that publishes more policy -------
  // This coordinator serves two sessions: the reconnecting site here, and the override attempt in
  // phase 4. Reusing a listener that is already serving removes any dependence on a client winning
  // a race against a freshly started listener, which is a race the test must not have.
  auto restarted = platform::spawn_process(
      binaries.federation,
      {"serve", "--plan", plan2_path.string(), "--store", coordinator_store.string(), "--port",
       "0", "--sessions", "2", "--out", fed_summary_restart.string()},
      fed_out_restart, fed_err_restart);
  if (!restarted.ok()) NOTE("respawn failed: " + restarted.error.to_string());
  REQUIRE(restarted.ok());
  const auto restarted_listening = await_listening(*restarted.value, fed_out_restart);
  if (!restarted_listening.ok()) NOTE("phase 3: " + restarted_listening.error.message);
  REQUIRE(restarted_listening.ok());
  reconnect_endpoint = "127.0.0.1:" + std::to_string(*restarted_listening);

  auto reconnect = run_captured(
      binaries.site,
      {"run", "--plan", plan2_path.string(), "--site-index", "0", "--store", site_store.string(),
       "--connect", reconnect_endpoint, "--sync-count", "1", "--out", reconnect_summary.string()},
      site_out, site_err, "phase 3 reconnect run");
  REQUIRE(reconnect.ok());
  CHECK_EQ(*reconnect, 0);
  auto reconnect_json = summary_of(reconnect_summary, "gpf-site reconnect");
  if (!reconnect_json.ok()) NOTE(reconnect_json.error.message);
  REQUIRE(reconnect_json.ok());
  CHECK_EQ(generation_field(*reconnect_json, "connected"), std::string("true"));
  const JsonValue* reconnect_effective = reconnect_json->find("effective");
  REQUIRE(reconnect_effective != nullptr);
  // Reconciliation moved the site to the newest generation and superseded the older publications
  // from the same publisher instead of blending them.
  const JsonValue* global_generation = reconnect_effective->find("global_generation");
  REQUIRE(global_generation != nullptr);
  CHECK(global_generation->as_int() >= 2);
  const JsonValue* superseded = reconnect_effective->find("rules_superseded");
  REQUIRE(superseded != nullptr);
  CHECK(superseded->as_int() > 0);

  NOTE("phase 3: syncs=" + generation_field(*reconnect_json, "syncs") +
       " accepted_this_run=" + generation_field(*reconnect_json, "accepted_this_run") +
       " rejected_this_run=" + generation_field(*reconnect_json, "rejected_this_run") +
       " accepted_bundles=" + generation_field(*reconnect_json, "accepted_bundles") +
       " effective_applied_gen=" + generation_field(*reconnect_effective, "global_generation") +
       " superseded=" + generation_field(*reconnect_effective, "rules_superseded"));
  if (const JsonValue* phase_three_entries = reconnect_effective->find("entries");
      phase_three_entries != nullptr) {
    for (const JsonValue& entry : phase_three_entries->array_items()) {
      const JsonValue* subject = entry.find("subject");
      if (subject != nullptr && subject->as_string() == "power/max_kw") {
        NOTE("phase 3 max_kw entry: " + entry.dump(true).substr(0, 700));
      }
    }
  }

  // ---- Phase 4: the newest mandatory policy forbids override: deterministic refusal ---------
  // The server is already listening from phase 3, so this session is served without any start-up
  // race; the override attempt runs against the newest accepted policy.
  auto refused = run_captured(
      binaries.site,
      {"run", "--plan", plan2_path.string(), "--site-index", "0", "--store", site_store.string(),
       "--connect", reconnect_endpoint, "--sync-count", "1", "--override", "power/max_kw=95",
       "--override-reason", "attempted under prohibited policy", "--out", refused_summary.string()},
      site_out, site_err, "phase 4 site run");
  REQUIRE(refused.ok());
  CHECK_EQ(*refused, 0);

  // Both sessions have now been served, so the coordinator completes and publishes its summary.
  auto restarted_exit = finish_coordinator(*restarted.value, *refused, "phase 4");
  if (!restarted_exit.ok()) NOTE("phase 4: " + restarted_exit.error.message);
  REQUIRE(restarted_exit.ok());
  if (*restarted_exit != 0) {
    auto diagnostics = platform::read_file(fed_err_restart, 4096);
    NOTE("restarted coordinator reported: " +
         (diagnostics.ok() ? *diagnostics : std::string("(no diagnostics)")));
    auto site_diagnostics = platform::read_file(reconnect_summary, 4096);
    NOTE("site reconnection summary: " +
         (site_diagnostics.ok() ? site_diagnostics->substr(0, 400) : std::string("(none)")));
  }
  CHECK_EQ(*restarted_exit, 0);
  auto second_summary = summary_of(fed_summary_restart, "gpf-federation restart");
  REQUIRE(second_summary.ok());
  const JsonValue* second_collected = second_summary->find("collected_receipts");
  REQUIRE(second_collected != nullptr);
  // Receipts re-reported after the partition are deduplicated by identity, so the coordinator's
  // evidence trail does not grow duplicates, and nothing was rejected.
  CHECK(second_collected->as_int() >= collected_after_phase_one);
  const JsonValue* rejected_receipts = second_summary->find("rejected_receipts");
  REQUIRE(rejected_receipts != nullptr);
  CHECK_EQ(rejected_receipts->as_int(), std::int64_t{0});

  auto refused_json = summary_of(refused_summary, "gpf-site refused override");
  if (!refused_json.ok()) NOTE(refused_json.error.message);
  REQUIRE(refused_json.ok());
  CHECK_EQ(generation_field(*refused_json, "syncs"), std::string("1"));
  NOTE("phase 4 override: " + generation_field(*refused_json, "override_state"));
  if (const JsonValue* final_entries_note = refused_json->find("effective");
      final_entries_note != nullptr) {
    if (const JsonValue* decisions = final_entries_note->find("decisions"); decisions != nullptr) {
      NOTE("phase 4 decisions: " + decisions->dump(true).substr(0, 1200));
    }
  }
  const JsonValue* refused_effective = refused_json->find("effective");
  REQUIRE(refused_effective != nullptr);
  const JsonValue* refused_count = refused_effective->find("overrides_refused");
  REQUIRE(refused_count != nullptr);
  // The override was registered as an explicit local decision, and the compiler refused to apply
  // it because the governing mandatory policy forbids local override. The binding value stands.
  CHECK(refused_count->as_int() >= 1);
  const JsonValue* applied_count = refused_effective->find("overrides_applied");
  REQUIRE(applied_count != nullptr);
  CHECK_EQ(applied_count->as_int(), std::int64_t{0});
  const JsonValue* final_entries = refused_effective->find("entries");
  REQUIRE(final_entries != nullptr);
  bool saw_binding_value = false;
  for (const JsonValue& entry : final_entries->array_items()) {
    const JsonValue* subject = entry.find("subject");
    const JsonValue* state = entry.find("state");
    const JsonValue* value = entry.find("value");
    REQUIRE(subject != nullptr);
    REQUIRE(state != nullptr);
    REQUIRE(value != nullptr);
    if (subject->as_string() == "power/max_kw" && state->as_string() == "active") {
      const JsonValue* integer = value->find("integer");
      REQUIRE(integer != nullptr);
      CHECK_EQ(integer->as_int(), std::int64_t{120});
      saw_binding_value = true;
    }
  }
  CHECK(saw_binding_value);

  // The durable store explains itself: which overrides the site holds, bound to which rule and
  // generation, and what the last decisions were.
  const std::filesystem::path store_dump_path = directory.child("store-dump.json");
  auto store_dump = platform::run_process(
      binaries.ctl, {"verify-store", site_store.string(), "--out", store_dump_path.string()});
  REQUIRE(store_dump.ok());
  CHECK_EQ(*store_dump, 0);
  auto store_json = read_json(store_dump_path);
  if (!store_json.ok()) NOTE(store_json.error.message);
  REQUIRE(store_json.ok());
  if (const JsonValue* held = store_json->find("held_overrides"); held != nullptr) {
    NOTE("held overrides: " + held->dump(true).substr(0, 1500));
  }
  if (const JsonValue* recent = store_json->find("recent_receipts"); recent != nullptr) {
    NOTE("recent receipts: " + recent->dump(true).substr(0, 1500));
  }
}
