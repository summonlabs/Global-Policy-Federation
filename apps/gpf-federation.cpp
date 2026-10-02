// gpf-federation — the federation coordinator process.
//
// Loads a declarative plan, commits delegated authority, the capability catalog and the published
// policy durably, then serves site sessions. Every published bundle is authorized before it is
// committed, and its generation is assigned by the coordinator rather than accepted from a file.

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
      "gpf-federation — Global Policy Federation coordinator\n"
      "\n"
      "usage:\n"
      "  gpf-federation serve --plan FILE --store DIR [--port N] [--bind ADDR] [--sessions N]\n"
      "                      [--seed N] [--out FILE]\n";
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
  std::cerr << "gpf-federation: " << message << "\n";
  return code;
}

// Publishes a plan bundle under the issuer's delegated authority. Rejections are reported, never
// silently skipped: an unauthorized publication is an error, not a warning.
Status publish_plan_bundle(FederationRuntime& runtime, const PolicyBundle& bundle, Timestamp now,
                           std::size_t* rejected) {
  std::string reason;
  PolicyBundle prepared = bundle;
  const Status status = runtime.publish_bundle(std::move(prepared), now, &reason);
  if (!status.ok()) {
    ++(*rejected);
    std::cerr << "gpf-federation: publication refused (" << reason << "): " << status.error.to_string()
              << "\n";
    return status;
  }
  return Status::success();
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
  if (command != "serve") {
    usage();
    return 2;
  }
  const auto options = parse_options(argc, argv, 2);
  const auto plan_option = options.find("plan");
  const auto store_option = options.find("store");
  if (plan_option == options.end() || store_option == options.end()) {
    return fail("serve needs --plan FILE and --store DIR");
  }
  auto plan = load_plan(plan_option->second);
  if (!plan) return fail("cannot load plan: " + plan.error.to_string());

  FederationConfig config;
  config.federation = plan->federation;
  config.root_member = plan->root_member;
  config.coordinator_site = plan->coordinator_site;
  config.store_directory = store_option->second;
  config.bind_address = options.count("bind") != 0 ? options.at("bind") : "127.0.0.1";
  config.port = static_cast<std::uint16_t>(option_u64(options, "port", 0));
  config.id_seed = option_u64(options, "seed", 1);

  auto runtime = FederationRuntime::open(config);
  if (!runtime) return fail("cannot open the coordinator: " + runtime.error.to_string());

  const Timestamp now{platform::system_now_millis()};
  const Status membership_status = (*runtime)->set_membership(plan->membership);
  if (!membership_status.ok()) return fail("cannot set membership: " + membership_status.error.to_string());
  const Status catalog_status = (*runtime)->set_catalog(plan->catalog, now);
  if (!catalog_status.ok()) return fail("cannot set catalog: " + catalog_status.error.to_string());

  for (const AuthorityGrant& grant : plan->grants) {
    const Status status = grant.parent.is_nil()
                              ? (*runtime)->add_root_grant(grant, now)
                              : (*runtime)->add_grant(grant, now, &plan->membership);
    if (!status.ok()) {
      return fail("cannot commit grant " + grant.id.to_string() + ": " + status.error.to_string(), 3);
    }
  }

  std::size_t rejected_publications = 0;
  for (const PolicyBundle& bundle : plan->bundles) {
    const Status status = publish_plan_bundle(**runtime, bundle, now, &rejected_publications);
    if (!status.ok()) {
      return fail("publication failed: " + status.error.to_string(), 3);
    }
  }
  for (const RevocationRecord& revocation : plan->revocations) {
    const Status status = (*runtime)->revoke(revocation, now, &plan->membership);
    if (!status.ok()) return fail("cannot commit revocation: " + status.error.to_string(), 3);
  }

  // Readiness is announced on stdout so a supervisor knows the exact port without guessing.
  std::cout << JsonValue::object({
                   {"event", JsonValue::text("listening")},
                   {"port", JsonValue::integer((*runtime)->port())},
                   {"bind", JsonValue::text(config.bind_address)},
                   {"published_bundles",
                    JsonValue::integer(static_cast<std::int64_t>((*runtime)->status().published_bundles))},
                   {"rejected_publications",
                    JsonValue::integer(static_cast<std::int64_t>(rejected_publications))},
               }).dump(true) << std::endl;

  const std::uint64_t sessions = option_u64(options, "sessions", 1);
  for (std::uint64_t i = 0; i < sessions; ++i) {
    const Status status = (*runtime)->serve_once(Timestamp{platform::system_now_millis()});
    if (!status.ok()) {
      if (status.error.code == ErrorCode::Cancelled) break;
      std::cerr << "gpf-federation: session failed: " << status.error.to_string() << "\n";
      break;
    }
  }

  const FederationStatus status = (*runtime)->status();
  JsonValue summary = JsonValue::object({
      {"event", JsonValue::text("summary")},
      {"sessions", JsonValue::integer(static_cast<std::int64_t>(status.sessions))},
      {"published_bundles", JsonValue::integer(static_cast<std::int64_t>(status.published_bundles))},
      {"rejected_publications", JsonValue::integer(static_cast<std::int64_t>(rejected_publications))},
      {"global_generation", JsonValue::integer(static_cast<std::int64_t>(status.global_generation.value))},
      {"grants", JsonValue::integer(static_cast<std::int64_t>(status.grants))},
      {"revocations", JsonValue::integer(static_cast<std::int64_t>(status.revocations))},
      {"collected_receipts", JsonValue::integer(static_cast<std::int64_t>(status.collected_receipts))},
      {"rejected_receipts", JsonValue::integer(static_cast<std::int64_t>(status.rejected_receipts))},
      {"catalog_generation", JsonValue::integer(static_cast<std::int64_t>(status.catalog_generation))},
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
  return 0;
}
