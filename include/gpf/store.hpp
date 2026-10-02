#pragma once
// Global Policy Federation — durable site state.
//
// Layout of a store directory:
//
//   MANIFEST                    identity, epoch, active snapshot and write-ahead log
//   snapshot-<sequence>.gpf     sealed snapshot of replayed state (JSON with its own digest)
//   wal-<sequence>.log          framed, checksummed write-ahead log
//
// Commit protocol for every state change:
//   validate -> append record -> flush to stable storage -> update in-memory sequence
// A record is authoritative only after the flush returns. Compaction writes a new snapshot, starts
// a new log, republishes the manifest atomically and only then removes the superseded files, so a
// compaction can never delete state that was not part of the snapshot it published.
//
// Recovery distinguishes three failures that must never be conflated:
//   * a clean log;
//   * a torn tail (the last record was not fully written) which is discarded and reported;
//   * interior corruption (a damaged record with valid records after it) which makes the store
//     refuse further writes instead of truncating through the damage and pretending recovery
//     succeeded.

#include "gpf/base.hpp"
#include "gpf/codec.hpp"
#include "gpf/effective.hpp"
#include "gpf/policy.hpp"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace gpf {

inline constexpr std::uint32_t kStoreFormatVersion = 1;

enum class StoreRecordKind : std::uint8_t {
  SiteDescriptor = 1,
  BundleAccepted = 2,
  BundleActivated = 3,
  LocalBundleRegistered = 4,
  OverrideRegistered = 5,
  OverrideRevoked = 6,
  ReceiptAppended = 7,
  ConflictRecorded = 8,
  RevocationApplied = 9,
  AuthorityGrantAdded = 10,
  AuthorityEpochAdvanced = 11,
  CapabilitySnapshotUpdated = 12,
  GenerationFenced = 13,
  CapabilityCatalogUpdated = 14,
};

const char* store_record_kind_name(StoreRecordKind kind) noexcept;
Result<StoreRecordKind> store_record_kind_from_name(std::string_view name);

struct StoreRecord {
  StoreRecordKind kind{StoreRecordKind::SiteDescriptor};
  Epoch writer_epoch{};
  SequenceNumber sequence{};
  Timestamp at{};
  std::string payload;  // canonical JSON of the recorded object
  Digest payload_digest{};
};

struct StoreIdentity {
  StoreId id;
  FederationId federation;
  MemberId member;
  SiteId site;
  Timestamp created_at{};
  std::uint32_t format_version{kStoreFormatVersion};
};

enum class RecoveryOutcome : std::uint8_t {
  CreatedNew = 0,
  Clean = 1,
  TornTailDiscarded = 2,
  InteriorCorruption = 3,
};

const char* recovery_outcome_name(RecoveryOutcome outcome) noexcept;

struct RecoveryReport {
  RecoveryOutcome outcome{RecoveryOutcome::Clean};
  std::uint64_t records_replayed{0};
  std::uint64_t bytes_discarded{0};
  std::uint64_t log_bytes{0};
  Epoch opened_epoch{};
  SequenceNumber last_sequence{};
  std::uint64_t reopen_count{0};
  bool writable{true};
  std::string detail;
  std::vector<std::string> notes;
};

struct StoreOpenOptions {
  std::filesystem::path directory;
  StoreIdentity identity;  // used when the store is created; persisted identity wins afterwards
  bool create_if_missing{true};
  std::uint64_t max_log_bytes{limits::kMaxWalBytes};
};

class DurableStore {
 public:
  DurableStore() = default;
  ~DurableStore();
  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;
  DurableStore(DurableStore&& other) noexcept;
  DurableStore& operator=(DurableStore&& other) noexcept;

  static Result<DurableStore> open(const StoreOpenOptions& options);

  const StoreIdentity& identity() const noexcept { return identity_; }
  const RecoveryReport& recovery() const noexcept { return report_; }
  Epoch epoch() const noexcept { return epoch_; }
  SequenceNumber last_sequence() const noexcept { return last_sequence_; }
  const std::filesystem::path& directory() const noexcept { return directory_; }
  const std::filesystem::path& log_path() const noexcept { return wal_name_; }
  bool is_writable() const noexcept { return writable_; }
  bool is_open() const noexcept { return open_; }

  // Appends one record and flushes it. Fenced: a writer whose epoch is not the current epoch is
  // refused, so a stale process cannot revive superseded state.
  Status append(Epoch writer_epoch, StoreRecordKind kind, std::string payload, Timestamp at);
  Status append(StoreRecordKind kind, std::string payload, Timestamp at);

  std::vector<StoreRecord> records() const;

  // Publishes a snapshot of exactly the state covered by the current sequence and rotates the log.
  Status compact(std::string snapshot_payload, Timestamp at);

  Status close();

 private:
  Status append_locked(Epoch writer_epoch, StoreRecordKind kind, const std::string& payload,
                       Timestamp at);
  // Confirms that this instance still owns the store: another process may have reopened it, which
  // advances the persisted epoch and fences every older writer.
  Status verify_ownership_locked() const;
  Status publish_manifest(std::uint64_t snapshot_sequence, const std::string& snapshot_name,
                          const std::string& wal_name, Timestamp at);
  Status load_manifest(const std::string& text);
  Status load_snapshot(std::string& snapshot_payload);
  void walk_log(const std::string& bytes);

  std::filesystem::path directory_;
  std::filesystem::path wal_name_;
  std::filesystem::path snapshot_name_;
  StoreIdentity identity_{};
  RecoveryReport report_{};
  Epoch epoch_{};
  SequenceNumber last_sequence_{};
  std::uint64_t reopen_count_{0};
  std::uint64_t snapshot_sequence_{0};
  Timestamp manifest_updated_at_{};
  std::vector<StoreRecord> records_;
  std::string snapshot_payload_;
  bool open_{false};
  bool writable_{true};
  Status load_failure_{};
  mutable std::mutex mutex_;
};

// ---------------------------------------------------------------------------------------
// Typed site state
// ---------------------------------------------------------------------------------------

// The replayed site state. Every field is derived from records; nothing is invented at load time.
struct PersistedSiteState {
  StoreIdentity identity{};
  SequenceNumber applied_sequence{};
  Generation applied_global_generation{};
  Generation local_generation{};
  SequenceNumber next_receipt_sequence{1};
  Epoch authority_epoch{};
  // When this node last verified contact with the federation. Durable, because the staleness
  // policy of accepted policy is measured from real verified contact, not from a restart.
  Timestamp last_federation_contact{};
  bool has_capabilities{false};
  SiteCapabilitySnapshot capabilities{};
  // What the federation has told this node about which capabilities exist at all. Persisted so a
  // restart during a partition can still tell "unsupported" from "not yet told".
  bool has_catalog{false};
  CapabilityCatalog catalog{};
  std::vector<PolicyBundle> accepted_bundles;
  std::vector<PolicyBundle> local_bundles;
  std::vector<LocalOverride> overrides;
  std::vector<Receipt> receipts;
  std::vector<ConflictRecord> conflicts;
  std::vector<RevocationRecord> revocations;
  std::vector<AuthorityGrant> grants;

  const PolicyBundle* find_bundle(PolicyBundleId id) const noexcept;
  const LocalOverride* find_override(OverrideId id) const noexcept;
};

// Applies exactly one record. Duplicate sequences are ignored (recorded as not applied); gaps and
// regressions are refused, which is what fences replayed or reordered history.
Status apply_record(PersistedSiteState& state, const StoreRecord& record, bool& applied);

// Replays a whole log into fresh state. Any record that cannot be applied stops the replay.
Result<PersistedSiteState> replay_records(const StoreIdentity& identity,
                                          const std::vector<StoreRecord>& records);

JsonValue site_state_to_json(const PersistedSiteState& state);
Result<PersistedSiteState> site_state_from_json(const JsonValue& value);

// Canonical payload encoders used by the record kinds.
std::string encode_bundle_record(const PolicyBundle& bundle);
std::string encode_override_record(const LocalOverride& record);
std::string encode_receipt_record(const Receipt& receipt);
std::string encode_conflict_record(const ConflictRecord& record);
std::string encode_revocation_record(const RevocationRecord& record);
std::string encode_grant_record(const AuthorityGrant& grant);
std::string encode_capability_record(const SiteCapabilitySnapshot& snapshot);
std::string encode_catalog_record(const CapabilityCatalog& catalog);
std::string encode_generation_record(Generation global_generation, Generation local_generation,
                                  Timestamp last_federation_contact = Timestamp{});
std::string encode_epoch_record(Epoch epoch);

}  // namespace gpf
