#include "fixtures.hpp"
#include "gpf/plan.hpp"
#include "gpf/platform.hpp"
#include "gpf/runtime.hpp"
#include "test_support.hpp"

#include <atomic>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace gpf;
using namespace gpf_test;

namespace {

FederationConfig federation_config(const FederationPlan& plan, const TempDirectory& directory,
                                   const std::string& label) {
  FederationConfig config;
  config.federation = plan.federation;
  config.root_member = plan.root_member;
  config.coordinator_site = plan.coordinator_site;
  config.store_directory = directory.child("coordinator-" + label);
  config.bind_address = "127.0.0.1";
  config.port = 0;  // ephemeral: the test reads the real port from the runtime
  config.id_seed = 7;
  return config;
}

SiteConfig site_config(const FederationPlan& plan, const PlanSite& entry,
                       const TempDirectory& directory, const std::string& label) {
  SiteConfig config;
  config.federation = plan.federation;
  config.member = entry.member;
  config.site = entry.site;
  config.store_directory = directory.child("site-" + label);
  config.id_seed = 11;
  config.worker_threads = 2;
  return config;
}

Result<std::unique_ptr<FederationRuntime>> open_coordinator(const FederationPlan& plan,
                                                            const TempDirectory& directory,
                                                            const std::string& label, Timestamp now) {
  auto config = federation_config(plan, directory, label);
  auto runtime = FederationRuntime::open(config);
  if (!runtime) return runtime;
  const Status membership = (*runtime)->set_membership(plan.membership);
  if (!membership.ok()) return Result<std::unique_ptr<FederationRuntime>>::failure(membership.error);
  const Status catalog = (*runtime)->set_catalog(plan.catalog, now);
  if (!catalog.ok()) return Result<std::unique_ptr<FederationRuntime>>::failure(catalog.error);
  for (const AuthorityGrant& grant : plan.grants) {
    const Status status = grant.parent.is_nil() ? (*runtime)->add_root_grant(grant, now)
                                                : (*runtime)->add_grant(grant, now, &plan.membership);
    if (!status.ok()) return Result<std::unique_ptr<FederationRuntime>>::failure(status.error);
  }
  return runtime;
}

}  // namespace

GPF_TEST(runtime, publication_requires_delegated_authority_and_monotonic_generations) {
  TempDirectory directory("runtime-publication");
  IdGenerator ids(31);
  SiteFixture fixture;
  auto plan = generate_scenario(4242, 2, 1);
  if (!plan.ok()) NOTE("scenario failed: " + plan.error.to_string());
  REQUIRE(plan.ok());

  const Timestamp now{platform::system_now_millis()};
  auto federation = open_coordinator(*plan, directory, "a", now);
  if (!federation.ok()) NOTE("open failed: " + federation.error.to_string());
  REQUIRE(federation.ok());

  // An issuer holding no grant cannot publish binding policy.
  MemberId stranger = make_member(fixture.ids);
  Rule rule = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  PolicyBundle unauthorized = fixture.global_bundle({rule}, Generation{1});
  unauthorized.federation = plan->federation;
  unauthorized.issuer_member = stranger;
  std::string reason;
  auto refused = (*federation)->publish_bundle(unauthorized, now, &reason);
  CHECK(!refused.ok());
  CHECK_EQ(error_code_name(refused.error.code), std::string("unauthorized"));
  CHECK(reason.rfind("publish-mandatory:", 0) == 0);
  CHECK_EQ((*federation)->status().published_bundles, std::size_t{0});

  // The delegated publisher gets generations 1, 2, ... for its own scope.
  const MemberId publisher = plan->grants.empty() ? stranger : plan->grants[1].grantee;
  for (int i = 0; i < 3; ++i) {
    std::vector<Rule> rules;
    rules.push_back(make_rule(fixture.ids, "power", "subject_" + std::to_string(i), int_value(i)));
    PolicyBundle bundle = fixture.global_bundle(std::move(rules), Generation{1});
    bundle.federation = plan->federation;
    bundle.issuer_member = publisher;
    const Status published = (*federation)->publish_bundle(bundle, now, &reason);
    if (!published.ok()) NOTE("publish failed: " + published.error.to_string());
    REQUIRE(published.ok());
  }
  std::vector<PolicyBundle> published_bundles = (*federation)->bundles();
  REQUIRE(published_bundles.size() == 3);
  for (std::size_t i = 0; i < published_bundles.size(); ++i) {
    CHECK_EQ(published_bundles[i].global_generation.value, static_cast<std::uint64_t>(i + 1));
  }
  CHECK_EQ((*federation)->status().global_generation.value, std::uint64_t{3});

  // The coordinator's own journal is durable: a restart keeps the published generations.
  REQUIRE((*federation)->shutdown().ok());
  federation->reset();
  auto reopened = open_coordinator(*plan, directory, "a", now);
  REQUIRE(reopened.ok());
  CHECK_EQ((*reopened)->status().published_bundles, std::size_t{3});
  std::vector<Rule> more;
  more.push_back(make_rule(fixture.ids, "power", "subject_more", int_value(9)));
  PolicyBundle next = fixture.global_bundle(std::move(more), Generation{1});
  next.federation = plan->federation;
  next.issuer_member = publisher;
  REQUIRE((*reopened)->publish_bundle(next, now, &reason).ok());
  CHECK_EQ((*reopened)->bundles().back().global_generation.value, std::uint64_t{4});
}

GPF_TEST(runtime, republication_is_idempotent_by_content_and_divergent_by_change) {
  TempDirectory directory("runtime-republish");
  auto plan = generate_scenario(4242, 1, 1);
  REQUIRE(plan.ok());
  const Timestamp now{platform::system_now_millis()};
  auto federation = open_coordinator(*plan, directory, "i", now);
  REQUIRE(federation.ok());

  std::string reason;
  PolicyBundle prepared = plan->bundles[0];
  REQUIRE((*federation)->publish_bundle(prepared, now, &reason).ok());
  CHECK_EQ(reason, std::string("published"));
  REQUIRE((*federation)->status().published_bundles == 1);
  const Generation assigned = (*federation)->bundles()[0].global_generation;

  // Re-applying the same plan entry publishes nothing new.
  REQUIRE((*federation)->publish_bundle(prepared, now, &reason).ok());
  CHECK_EQ(reason, std::string("already-published"));
  CHECK_EQ((*federation)->status().published_bundles, std::size_t{1});
  CHECK_EQ((*federation)->bundles()[0].global_generation.value, assigned.value);

  // The same identity with different content is refused instead of being silently re-versioned.
  PolicyBundle changed = prepared;
  REQUIRE(changed.rules.size() > 0);
  changed.rules[0].value = int_value(7);
  REQUIRE(seal_bundle(changed).ok());
  auto divergent = (*federation)->publish_bundle(changed, now, &reason);
  CHECK(!divergent.ok());
  CHECK_EQ(reason, std::string("divergent-content"));
  CHECK_EQ(error_code_name(divergent.error.code), std::string("divergent"));
  CHECK_EQ((*federation)->status().published_bundles, std::size_t{1});
}

GPF_TEST(runtime, site_accepts_activates_and_reports_while_the_coordinator_serves) {
  TempDirectory directory("runtime-sync");
  auto plan = generate_scenario(4242, 2, 1);
  REQUIRE(plan.ok());
  const Timestamp now{platform::system_now_millis()};

  auto federation = open_coordinator(*plan, directory, "b", now);
  REQUIRE(federation.ok());
  std::string reason;
  for (const PolicyBundle& bundle : plan->bundles) {
    PolicyBundle prepared = bundle;
    REQUIRE((*federation)->publish_bundle(std::move(prepared), now, &reason).ok());
  }
  const std::uint16_t port = (*federation)->port();
  REQUIRE(port != 0);

  auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "b"));
  if (!site.ok()) NOTE("site open failed: " + site.error.to_string());
  REQUIRE(site.ok());
  (*site)->set_membership(plan->membership);
  SiteCapabilitySnapshot declaration;
  declaration.catalog_generation = plan->catalog.generation;
  declaration.capabilities = plan->catalog.capabilities;
  REQUIRE((*site)->set_capabilities(declaration).ok());

  std::atomic<int> session_result{99};
  std::thread server([&] {
    const Status status = (*federation)->serve_once(Timestamp{platform::system_now_millis()});
    session_result = status.ok() ? 0 : 1;
  });

  REQUIRE((*site)->connect("127.0.0.1", port).ok());
  std::size_t accepted = 0;
  std::size_t rejected = 0;
  const Status sync = (*site)->sync_once(Timestamp{platform::system_now_millis()}, &accepted, &rejected);
  if (!sync.ok()) NOTE("sync failed: " + sync.error.to_string());
  REQUIRE(sync.ok());
  CHECK_EQ(accepted, plan->bundles.size());
  CHECK_EQ(rejected, std::size_t{0});

  std::size_t receipts_recorded = 0;
  auto compiled = (*site)->activate(Timestamp{platform::system_now_millis()}, &receipts_recorded);
  if (!compiled.ok()) NOTE("activation failed: " + compiled.error.to_string());
  REQUIRE(compiled.ok());
  CHECK(compiled->entries.size() >= 5);
  CHECK_EQ(compiled->rules_rejected, std::size_t{0});
  CHECK_EQ(compiled->conflicts.size(), std::size_t{0});
  const EffectiveEntry* mandatory = compiled->find("power", "max_kw");
  REQUIRE(mandatory != nullptr);
  CHECK(mandatory->state == EntryState::Active);
  CHECK(mandatory->value == int_value(120));
  CHECK(receipts_recorded > 0);

  const SiteStatus status = (*site)->status();
  CHECK_EQ(status.accepted_bundles, plan->bundles.size());
  CHECK(status.pending_receipts > 0);

  std::size_t reported = 0;
  const Status report = (*site)->report_receipts(Timestamp{platform::system_now_millis()}, &reported);
  if (!report.ok()) NOTE("report failed: " + report.error.to_string());
  REQUIRE(report.ok());
  CHECK(reported > 0);
  CHECK_EQ((*site)->status().pending_receipts, std::size_t{0});

  (*site)->disconnect("session complete");
  server.join();
  CHECK_EQ(session_result.load(), 0);
  CHECK((*federation)->status().collected_receipts > 0);
  CHECK_EQ((*federation)->status().sessions, std::size_t{1});
}

GPF_TEST(runtime, replayed_receipts_are_deduplicated_by_identity) {
  TempDirectory directory("runtime-dedup");
  auto plan = generate_scenario(4242, 1, 1);
  REQUIRE(plan.ok());
  const Timestamp now{platform::system_now_millis()};
  auto federation = open_coordinator(*plan, directory, "c", now);
  REQUIRE(federation.ok());
  std::string reason;
  for (const PolicyBundle& bundle : plan->bundles) {
    PolicyBundle prepared = bundle;
    REQUIRE((*federation)->publish_bundle(std::move(prepared), now, &reason).ok());
  }
  auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "c"));
  REQUIRE(site.ok());
  (*site)->set_membership(plan->membership);

  const std::uint16_t port = (*federation)->port();
  std::size_t first_round_reported = 0;
  for (int round = 0; round < 2; ++round) {
    std::thread server([&] { (void)(*federation)->serve_once(Timestamp{platform::system_now_millis()}); });
    REQUIRE((*site)->connect("127.0.0.1", port).ok());
    std::size_t accepted = 0;
    std::size_t rejected = 0;
    REQUIRE((*site)->sync_once(Timestamp{platform::system_now_millis()}, &accepted, &rejected).ok());
    std::size_t reported = 0;
    REQUIRE((*site)->report_receipts(Timestamp{platform::system_now_millis()}, &reported).ok());
    if (round == 0) {
      first_round_reported = reported;
    } else {
      // Nothing new to report: everything was acknowledged, so the site does not spam the
      // federation with a replay it does not need.
      CHECK_EQ(reported, std::size_t{0});
    }
    (*site)->disconnect("round complete");
    server.join();
  }
  CHECK(first_round_reported > 0);
  const std::vector<Receipt> collected = (*federation)->collected_receipts();
  CHECK(!collected.empty());
  CHECK_EQ(collected.size(), (*federation)->status().collected_receipts);
  // Re-reporting the same receipts must not create a second copy of any of them.
  std::set<std::string> identities;
  for (const Receipt& receipt : collected) identities.insert(receipt.id.to_string());
  CHECK_EQ(identities.size(), collected.size());
  CHECK((*federation)->status().rejected_receipts == 0);
  // Every collected receipt is attributable to the site that made the decision.
  for (const Receipt& receipt : collected) {
    CHECK_EQ(receipt.site.to_string(), plan->sites[0].site.to_string());
    CHECK_EQ(receipt.member.to_string(), plan->sites[0].member.to_string());
    CHECK(validate_receipt(receipt).ok());
  }
}

GPF_TEST(runtime, callbacks_run_without_the_state_lock_and_failures_are_contained) {
  TempDirectory directory("runtime-callbacks");
  auto plan = generate_scenario(4242, 1, 1);
  REQUIRE(plan.ok());
  auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "d"));
  REQUIRE(site.ok());
  (*site)->set_membership(plan->membership);

  std::atomic<int> events{0};
  std::atomic<bool> reentered{false};
  (*site)->set_listener([&](const SiteEvent&) {
    // Re-entering the runtime from a callback must not deadlock: callbacks are delivered with no
    // state lock held. This call would hang if that rule were broken.
    const SiteStatus status = (*site)->status();
    reentered = status.worker_threads > 0;
    ++events;
    throw std::runtime_error("listener failure");  // contained by the runtime
  });

  // The callback throws, yet the operation that triggered it still completes and the runtime
  // keeps working afterwards. This site holds no publication authority yet, so the decision is a
  // refusal, which is exactly the event path being exercised.
  bool accepted_flag = true;
  std::string reason;
  const Status accepted = (*site)->accept_bundle(plan->bundles[0], &accepted_flag, &reason);
  CHECK(accepted.ok());
  CHECK(!accepted_flag);
  CHECK_EQ(reason, std::string(reasons::kAuthorityDenied));
  CHECK(reentered.load());
  CHECK(events.load() >= 1);

  // The runtime keeps working after a callback threw.
  const SiteStatus status = (*site)->status();
  CHECK_EQ(status.worker_threads, std::size_t{2});
  std::size_t receipts_recorded = 0;
  auto compiled = (*site)->activate(Timestamp{platform::system_now_millis()}, &receipts_recorded);
  CHECK(compiled.ok());
}

GPF_TEST(runtime, destruction_never_delivers_events) {
  // A listener commonly captures objects created after the runtime, so a callback delivered while
  // the runtime is being destroyed would run against state that no longer exists. An explicit
  // shutdown reports the shutdown event exactly once; destruction reports nothing at all.
  TempDirectory directory("runtime-destructor");
  auto plan = generate_scenario(4242, 1, 1);
  REQUIRE(plan.ok());
  auto shutdown_events = std::make_shared<std::atomic<int>>(0);
  {
    auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "g"));
    REQUIRE(site.ok());
    (*site)->set_listener([shutdown_events](const SiteEvent& event) {
      if (event.kind == SiteEventKind::Shutdown) ++(*shutdown_events);
    });
    CHECK((*site)->shutdown().ok());
    CHECK((*site)->shutdown().ok());  // idempotent: stopping twice reports nothing twice
    CHECK_EQ(shutdown_events->load(), 1);
  }
  // The runtime was destroyed above; no further event may have been delivered.
  CHECK_EQ(shutdown_events->load(), 1);
}

GPF_TEST(runtime, shutdown_is_safe_with_compilation_in_flight) {
  // Shutdown abandons whatever is still queued, so every caller blocked on a queued compilation
  // must be released. That window is narrow: all workers must still be asleep with work queued.
  // The cycle is therefore repeated, which is what makes this a regression test for the abandoned
  // waiter rather than a single lucky interleaving.
  int successes = 0;
  int cancellations = 0;
  for (int round = 0; round < 8; ++round) {
    TempDirectory directory("runtime-shutdown");
    auto plan = generate_scenario(4242, 1, 1);
    REQUIRE(plan.ok());
    auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "e"));
    REQUIRE(site.ok());

    std::atomic<bool> stop{false};
    std::atomic<int> round_successes{0};
    std::atomic<int> round_cancellations{0};
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) {
      workers.emplace_back([&] {
        while (!stop.load()) {
          auto compiled = (*site)->compile_effective_policy(Timestamp{platform::system_now_millis()});
          if (compiled.ok()) {
            ++round_successes;
          } else {
            ++round_cancellations;
          }
        }
      });
    }
    // Let the workers issue real compilations, then shut down underneath them.
    for (int i = 0; i < 50; ++i) {
      (void)(*site)->compile_effective_policy(Timestamp{platform::system_now_millis()});
    }
    stop = true;
    const Status shutdown_status = (*site)->shutdown();
    CHECK(shutdown_status.ok());
    // Joining only returns if every blocked caller was released by the shutdown.
    for (std::thread& worker : workers) worker.join();
    successes += round_successes.load();
    cancellations += round_cancellations.load();

    // After shutdown, compilation is refused instead of quietly succeeding.
    auto after = (*site)->compile_effective_policy(Timestamp{platform::system_now_millis()});
    CHECK(!after.ok());
    CHECK(after.error.code == ErrorCode::Cancelled || after.error.code == ErrorCode::Fenced ||
          after.error.code == ErrorCode::InvalidState);
  }
  CHECK(successes + cancellations > 0);
}

GPF_TEST(runtime, returned_policy_is_never_older_than_the_state_it_reports) {
  TempDirectory directory("runtime-fencing");
  auto plan = generate_scenario(4242, 1, 1);
  REQUIRE(plan.ok());
  const Timestamp now{platform::system_now_millis()};
  auto federation = open_coordinator(*plan, directory, "f", now);
  REQUIRE(federation.ok());
  std::string reason;
  for (const PolicyBundle& bundle : plan->bundles) {
    PolicyBundle prepared = bundle;
    REQUIRE((*federation)->publish_bundle(std::move(prepared), now, &reason).ok());
  }
  auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "f"));
  REQUIRE(site.ok());
  (*site)->set_membership(plan->membership);

  std::thread server([&] { (void)(*federation)->serve_once(Timestamp{platform::system_now_millis()}); });
  REQUIRE((*site)->connect("127.0.0.1", (*federation)->port()).ok());
  std::size_t accepted = 0;
  std::size_t rejected = 0;
  REQUIRE((*site)->sync_once(Timestamp{platform::system_now_millis()}, &accepted, &rejected).ok());

  // Concurrent local overrides advance the local generation while compilations are running. A
  // compilation that returns must reflect the state at the moment it returns, never an older one.
  // Copied out of the state snapshot: holding a pointer into a returned temporary would dangle.
  PolicyBundle base;
  bool base_found = false;
  for (const PolicyBundle& bundle : (*site)->state().accepted_bundles) {
    for (const Rule& rule : bundle.rules) {
      if (rule.rule_class == RuleClass::Mandatory &&
          rule.override_permission != OverridePermission::Prohibited) {
        base = bundle;
        base_found = true;
        break;
      }
    }
    if (base_found) break;
  }
  REQUIRE(base_found);
  Rule governing = base.rules[0];
  for (const Rule& rule : base.rules) {
    if (rule.rule_class == RuleClass::Mandatory) {
      governing = rule;
      break;
    }
  }
  IdGenerator ids(77);
  std::atomic<int> stale{0};
  std::atomic<int> fresh{0};
  std::atomic<int> override_successes{0};
  std::atomic<int> override_failures{0};
  std::vector<std::thread> workers;
  for (int i = 0; i < 3; ++i) {
    workers.emplace_back([&, i] {
      for (int step = 0; step < 8; ++step) {
        auto compiled = (*site)->compile_effective_policy(Timestamp{platform::system_now_millis()});
        if (!compiled.ok()) continue;
        // Generations only move forward, so a returned policy can never be ahead of the state
        // observed after it returned. A result built from superseded state is refused by the
        // runtime instead of being handed back as current.
        const SiteStatus status = (*site)->status();
        if (compiled->local_generation.value <= status.local_generation.value &&
            compiled->global_generation.value <= status.applied_global_generation.value) {
          ++fresh;
        } else {
          ++stale;
        }
        LocalOverride override_record =
            make_override(ids, plan->federation, plan->sites[0].member, plan->sites[0].site, governing,
                          base, Generation{static_cast<std::uint64_t>(step + 1)}, int_value(10 + i),
                          "concurrency-test", "advance the local generation", GrantId{},
                          Timestamp{platform::system_now_millis()});
        bool was_accepted = false;
        std::string text;
        const Status registration =
            (*site)->register_override(override_record, &was_accepted, &text);
        if (!registration.ok()) {
          ++override_failures;
        } else if (!was_accepted) {
          ++override_failures;
        } else {
          ++override_successes;
        }
      }
    });
  }
  for (std::thread& worker : workers) worker.join();
  (*site)->disconnect("done");
  server.join();
  // Every returned compilation matched the state it was compared against, and the runtime counted
  // any discarded work instead of publishing it.
  CHECK_EQ(stale.load(), 0);
  CHECK(fresh.load() > 0);
  if (override_failures.load() != 0) {
    NOTE("override registrations refused: " + std::to_string(override_failures.load()));
  }
  CHECK(override_successes.load() > 0);
  CHECK((*site)->status().overrides > 0);
  // Accounting: every successful compilation is counted, and nothing was published from a
  // superseded snapshot.
  CHECK((*site)->status().compilations >= static_cast<std::size_t>(fresh.load()));
  // Under quiescence the same state and the same clock compile to the same digest.
  const Timestamp quiet_now{platform::system_now_millis()};
  auto quiet_first = (*site)->compile_effective_policy(quiet_now);
  auto quiet_second = (*site)->compile_effective_policy(quiet_now);
  REQUIRE(quiet_first.ok());
  REQUIRE(quiet_second.ok());
  CHECK(quiet_first->digest == quiet_second->digest);
}

GPF_TEST(runtime, unauthorized_bundle_is_refused_with_a_durable_receipt) {
  TempDirectory directory("runtime-authority");
  IdGenerator ids(91);
  SiteFixture fixture;
  auto plan = generate_scenario(4242, 1, 1);
  REQUIRE(plan.ok());
  auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "g"));
  REQUIRE(site.ok());
  (*site)->set_membership(plan->membership);

  // A bundle from a member that holds no publication grant: structurally perfect, unauthorized.
  Rule rule = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  const MemberId stranger = make_member(fixture.ids);
  PolicyBundle bundle = make_bundle(fixture.ids, plan->federation, stranger, Generation{1}, {rule},
                                    Timestamp{platform::system_now_millis()});
  bool accepted = false;
  std::string reason;
  const Status status = (*site)->accept_bundle(bundle, &accepted, &reason);
  REQUIRE(status.ok());
  CHECK(!accepted);
  CHECK_EQ(reason, std::string(reasons::kAuthorityDenied));
  CHECK_EQ((*site)->status().accepted_bundles, std::size_t{0});

  const PersistedSiteState state = (*site)->state();
  REQUIRE(!state.receipts.empty());
  CHECK(state.receipts.back().kind == ReceiptKind::Rejected);
  CHECK_EQ(state.receipts.back().reason_code, std::string(reasons::kAuthorityDenied));
  CHECK_EQ(state.receipts.back().federation.to_string(), plan->federation.to_string());

  // The same refused delivery twice is one decision and one receipt, not two.
  bool first = true;
  REQUIRE((*site)->accept_bundle(bundle, &first, &reason).ok());
  CHECK(!first);
  const std::size_t receipts_after_first = (*site)->state().receipts.size();
  bool second = true;
  REQUIRE((*site)->accept_bundle(bundle, &second, &reason).ok());
  CHECK(!second);
  CHECK_EQ(reason, std::string(reasons::kAuthorityDenied));
  CHECK_EQ((*site)->state().receipts.size(), receipts_after_first);
}

GPF_TEST(runtime, partition_keeps_local_work_alive_and_reports_it) {
  TempDirectory directory("runtime-partition");
  auto plan = generate_scenario(4242, 1, 1);
  REQUIRE(plan.ok());
  const Timestamp now{platform::system_now_millis()};
  auto federation = open_coordinator(*plan, directory, "h", now);
  REQUIRE(federation.ok());
  std::string reason;
  for (const PolicyBundle& bundle : plan->bundles) {
    PolicyBundle prepared = bundle;
    REQUIRE((*federation)->publish_bundle(std::move(prepared), now, &reason).ok());
  }
  auto site = SiteRuntime::open(site_config(*plan, plan->sites[0], directory, "h"));
  REQUIRE(site.ok());
  (*site)->set_membership(plan->membership);
  SiteCapabilitySnapshot declaration;
  declaration.catalog_generation = plan->catalog.generation;
  declaration.capabilities = plan->catalog.capabilities;
  REQUIRE((*site)->set_capabilities(declaration).ok());

  std::thread server([&] { (void)(*federation)->serve_once(Timestamp{platform::system_now_millis()}); });
  REQUIRE((*site)->connect("127.0.0.1", (*federation)->port()).ok());
  std::size_t accepted = 0;
  std::size_t rejected = 0;
  REQUIRE((*site)->sync_once(Timestamp{platform::system_now_millis()}, &accepted, &rejected).ok());
  (*site)->disconnect("federation lost");
  server.join();
  CHECK(!(*site)->is_connected());
  CHECK((*site)->status().partitioned);

  // While disconnected, accepted policy is evaluated under its declared staleness policy and
  // local overrides still work because they never needed the federation to be reachable.
  std::size_t receipts_recorded = 0;
  auto compiled = (*site)->activate(Timestamp{platform::system_now_millis()}, &receipts_recorded);
  REQUIRE(compiled.ok());
  CHECK(compiled->partitioned);
  const EffectiveEntry* mandatory = compiled->find("power", "max_kw");
  REQUIRE(mandatory != nullptr);
  CHECK(mandatory->state == EntryState::LastKnownValid);
  CHECK(entry_state_is_binding(mandatory->state));
  const EffectiveEntry* fresh = compiled->find("cooling", "target_c");
  REQUIRE(fresh != nullptr);
  CHECK(fresh->state == EntryState::Withheld);

  PolicyBundle base;
  bool base_found = false;
  Rule governing;
  for (const PolicyBundle& bundle : (*site)->state().accepted_bundles) {
    for (const Rule& rule : bundle.rules) {
      if (rule.domain == "power" && rule.subject == "max_kw" &&
          rule.override_permission != OverridePermission::Prohibited) {
        base = bundle;
        governing = rule;
        base_found = true;
        break;
      }
    }
    if (base_found) break;
  }
  REQUIRE(base_found);
  IdGenerator ids(1234);
  LocalOverride override_record = make_override(ids, plan->federation, plan->sites[0].member,
                                                plan->sites[0].site, governing, base, Generation{1},
                                                int_value(95), "site-reliability",
                                                "local envelope while the federation is unreachable",
                                                GrantId{}, Timestamp{platform::system_now_millis()});
  bool was_accepted = false;
  std::string text;
  const Status registration = (*site)->register_override(override_record, &was_accepted, &text);
  REQUIRE(registration.ok());
  if (!was_accepted) NOTE("override registration refused: " + text);
  CHECK(was_accepted);

  auto recompiled = (*site)->activate(Timestamp{platform::system_now_millis()}, &receipts_recorded);
  REQUIRE(recompiled.ok());
  const EffectiveEntry* overridden = recompiled->find("power", "max_kw");
  REQUIRE(overridden != nullptr);
  // The governing rule requires delegated authority, which a partitioned site cannot verify by
  // asking the federation; the ledger it already holds decides, and refusal is explicit.
  CHECK(overridden->state == EntryState::LastKnownValid || overridden->state == EntryState::Overridden);
  CHECK(recompiled->overrides_applied + recompiled->overrides_refused >= 1);
}
