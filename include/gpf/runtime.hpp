#pragma once
// Global Policy Federation — site agent and federation coordinator runtimes.
//
// Ownership and locking rules, stated once and reviewed on every call path:
//
//   * One mutex protects site state. It is not held across a socket operation, an event callback,
//     or a worker join.
//   * Store appends are the commit point of a decision and are performed while holding the state
//     lock, so two decisions cannot interleave their validation and their commit. A store has its
//     own internal lock; the ordering is always state lock before store lock.
//   * Event callbacks run after the state lock is released, so a callback may call back into the
//     runtime. A throwing callback is contained and reported, never unwound through a lock.
//   * Compilation runs on a bounded worker pool. Every task carries the store epoch and the
//     generations it was built from; a result whose epoch or generation is no longer current is
//     discarded as stale rather than published. Cancelled or superseded work never reports success.
//   * Shutdown sets a stopping flag, notifies waiters, closes the socket, then joins workers.
//     Workers never need the state lock to finish, so shutdown cannot deadlock against them.

#include "gpf/authority.hpp"
#include "gpf/effective.hpp"
#include "gpf/net.hpp"
#include "gpf/policy.hpp"
#include "gpf/protocol.hpp"
#include "gpf/store.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace gpf {

// ---------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------

enum class SiteEventKind : std::uint8_t {
  StoreOpened = 0,
  BundleAccepted = 1,
  BundleRejected = 2,
  OverrideRegistered = 3,
  OverrideRefused = 4,
  PolicyApplied = 5,
  ConflictRecorded = 6,
  Connected = 7,
  Disconnected = 8,
  ReceiptsReported = 9,
  Shutdown = 10,
  CallbackFailed = 11,
};

const char* site_event_kind_name(SiteEventKind kind) noexcept;

struct SiteEvent {
  SiteEventKind kind{SiteEventKind::StoreOpened};
  std::string reason_code;
  std::string detail;
  PolicyBundleId bundle;
  OverrideId override_id;
  Generation generation{};
  std::size_t count{0};
};

using SiteEventListener = std::function<void(const SiteEvent&)>;

// ---------------------------------------------------------------------------------------
// Site agent
// ---------------------------------------------------------------------------------------

struct SiteConfig {
  FederationId federation;
  MemberId member;
  SiteId site;
  // Trust anchor of the federation this site belongs to. It is configuration supplied by
  // onboarding, never inferred from membership.
  MemberId root_member;
  std::filesystem::path store_directory;
  SemanticVersion runtime_version{1, 0, 0};
  std::uint64_t id_seed{1};
  std::size_t worker_threads{2};
};

struct SiteStatus {
  Generation applied_global_generation{};
  Generation local_generation{};
  Epoch store_epoch{};
  Epoch authority_epoch{};
  std::size_t accepted_bundles{0};
  std::size_t local_bundles{0};
  std::size_t overrides{0};
  std::size_t receipts{0};
  std::size_t conflicts{0};
  std::size_t pending_receipts{0};
  std::size_t reported_receipts{0};
  std::size_t compilations{0};
  std::size_t stale_compilations{0};
  std::size_t worker_threads{0};
  std::size_t queued_tasks{0};
  bool partitioned{true};
  bool connected{false};
  bool stopping{false};
};

class SiteRuntime {
 public:
  SiteRuntime();
  ~SiteRuntime();
  SiteRuntime(const SiteRuntime&) = delete;
  SiteRuntime& operator=(const SiteRuntime&) = delete;

  static Result<std::unique_ptr<SiteRuntime>> open(const SiteConfig& config);

  void set_listener(SiteEventListener listener);
  // Membership truth consumed from the federation; needed only to resolve member-scoped grants
  // against this site's own decisions.
  void set_membership(MembershipBinding membership);

  // Durable local operations: each returns only after its record is flushed.
  Status accept_bundle(const PolicyBundle& bundle, bool* accepted, std::string* reason_code);
  Status register_override(const LocalOverride& record, bool* accepted, std::string* reason_code);
  Status record_receipt(const Receipt& receipt);
  Status set_capabilities(const SiteCapabilitySnapshot& snapshot);

  // Applies one federation sync: grants, revocations, capability catalog and policy. Acceptance
  // and activation are separate steps and are recorded separately.
  Status ingest_sync(const SyncResponseMessage& response, Timestamp now, std::size_t* accepted_count,
                     std::size_t* rejected_count);

  // Compiles effective policy on a worker thread. Fenced: a result built from superseded state is
  // discarded and reported as a stale-generation failure rather than published.
  Result<EffectivePolicy> compile_effective_policy(Timestamp now);

  // Activation: compiles policy and commits the resulting generations, the verified contact time
  // and every receipt the compilation produced. Acceptance and activation are separate durable
  // steps, and this is the second one.
  Result<EffectivePolicy> activate(Timestamp now, std::size_t* receipts_recorded);

  Status connect(const std::string& host, std::uint16_t port);
  Status sync_once(Timestamp now, std::size_t* accepted_count, std::size_t* rejected_count);
  Status report_receipts(Timestamp now, std::size_t* reported);
  void disconnect(const std::string& reason);
  bool is_connected() const;

  // Stops the runtime and reports the shutdown event exactly once. Destruction stops the runtime
  // without reporting anything, because a listener may already have outlived the objects it
  // captured.
  Status shutdown();

  SiteStatus status() const;
  PersistedSiteState state() const;
  AuthorityLedger ledger() const;
  const StoreIdentity& identity() const;

 private:
  struct CompileTask {
    PersistedSiteState state;
    MembershipBinding membership;
    CapabilityCatalog catalog;
    AuthorityLedger ledger;
    Epoch store_epoch{};
    Generation global_generation{};
    Generation local_generation{};
    Timestamp now{};
    Timestamp last_contact_at{};
    bool partitioned{true};
    Result<EffectivePolicy> result;
    bool done{false};
  };

  void worker_loop();
  Result<EffectivePolicy> build_effective(const CompileTask& task) const;
  void emit(const SiteEvent& event) const;
  Status append_receipt_locked(Receipt receipt, Timestamp now);
  bool authority_allows_bundle_locked(const PolicyBundle& bundle, Timestamp now,
                                      std::string* reason) const;
  void start_workers();
  void stop_workers();
  Status shutdown_internal(bool report_event);

  mutable std::mutex mutex_;
  std::condition_variable work_available_;
  std::condition_variable work_finished_;
  std::deque<std::shared_ptr<CompileTask>> queue_;
  std::vector<std::thread> workers_;
  std::unique_ptr<DurableStore> store_;
  std::unique_ptr<net::Socket> socket_;
  SiteEventListener listener_;
  SiteConfig config_{};
  PersistedSiteState state_{};
  AuthorityLedger ledger_{};
  MembershipBinding membership_{};
  CapabilityCatalog catalog_{};
  SequenceNumber local_sequence_{};
  Timestamp last_contact_at_{};
  std::vector<Receipt> pending_receipts_;
  SiteStatus status_{};
  bool stopping_{false};
  bool workers_started_{false};
  bool stopped_{false};
};

// ---------------------------------------------------------------------------------------
// Federation coordinator
// ---------------------------------------------------------------------------------------

struct FederationConfig {
  FederationId federation;
  MemberId root_member;
  // The coordinator stores its own journal as a control-plane node of the federation.
  SiteId coordinator_site;
  std::filesystem::path store_directory;
  std::string bind_address{"127.0.0.1"};
  std::uint16_t port{0};
  std::uint64_t id_seed{1};
  SemanticVersion runtime_version{1, 0, 0};
};

struct FederationStatus {
  Generation global_generation{};
  Epoch authority_epoch{};
  std::size_t published_bundles{0};
  std::size_t grants{0};
  std::size_t revocations{0};
  std::size_t collected_receipts{0};
  std::size_t sessions{0};
  std::size_t rejected_receipts{0};
  std::size_t catalog_generation{0};
  bool listening{false};
  bool stopping{false};
};

class FederationRuntime {
 public:
  FederationRuntime();
  ~FederationRuntime();
  FederationRuntime(const FederationRuntime&) = delete;
  FederationRuntime& operator=(const FederationRuntime&) = delete;

  static Result<std::unique_ptr<FederationRuntime>> open(const FederationConfig& config);

  Status add_root_grant(const AuthorityGrant& grant, Timestamp now);
  Status add_grant(const AuthorityGrant& grant, Timestamp now, const MembershipBinding* membership);
  Status set_catalog(const CapabilityCatalog& catalog, Timestamp now);
  Status set_membership(MembershipBinding membership);

  // Validates the publisher's delegated authority, assigns the next generation for that publisher
  // and scope, seals the bundle and commits it durably before it can be propagated.
  Status publish_bundle(PolicyBundle bundle, Timestamp now, std::string* reason_code);

  Status revoke(RevocationRecord record, Timestamp now, const MembershipBinding* membership);

  // Accepts and serves exactly one session, then returns. Blocking until a peer connects; stop()
  // closes the listener to unblock it.
  Status serve_once(Timestamp now);
  void stop();
  Status shutdown();

  FederationStatus status() const;
  std::vector<PolicyBundle> bundles() const;
  // Receipts collected from sites, deduplicated by receipt identity.
  std::vector<Receipt> collected_receipts() const;
  AuthorityLedger ledger() const;
  CapabilityCatalog catalog() const;
  std::uint16_t port() const;

 private:
  Status handle_session(net::Socket& socket, Timestamp now);
  SyncResponseMessage build_sync_response_locked(const SyncRequestMessage& request) const;
  Status persist_bundle_locked(const PolicyBundle& bundle, Timestamp now);
  Status append_record_locked(StoreRecordKind kind, std::string payload, Timestamp now);

  mutable std::mutex mutex_;
  std::unique_ptr<DurableStore> store_;
  std::unique_ptr<net::Socket> listener_;
  FederationConfig config_{};
  PersistedSiteState state_{};
  AuthorityLedger ledger_{};
  MembershipBinding membership_{};
  CapabilityCatalog catalog_{};
  FederationStatus status_{};
  // Read by the serve and session paths without the state lock, so it is atomic by construction.
  std::atomic<bool> stopping_{false};
};

}  // namespace gpf
