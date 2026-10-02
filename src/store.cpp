#include "gpf/store.hpp"

#include "gpf/platform.hpp"

#include <algorithm>
#include <cstring>
#include <set>

namespace gpf {
namespace {

constexpr char kFrameMagic[4] = {'G', 'P', 'F', '1'};
constexpr std::size_t kFrameHeaderSize = 38;  // magic(4) kind(1) flags(1) length(4) crc(4) epoch(8) seq(8) at(8)

std::string manifest_name() { return "MANIFEST"; }

std::string snapshot_file_name(std::uint64_t sequence) {
  return "snapshot-" + std::to_string(sequence) + ".gpf";
}

std::string wal_file_name(std::uint64_t sequence) { return "wal-" + std::to_string(sequence) + ".log"; }

void put_u32(std::string& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<char>((value >> (i * 8)) & 0xFFu));
}

void put_u64(std::string& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<char>((value >> (i * 8)) & 0xFFu));
}

std::uint32_t read_u32(const std::string& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset + static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  return value;
}

std::uint64_t read_u64(const std::string& bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[offset + static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  return value;
}

bool frame_magic_matches(const std::string& bytes, std::size_t offset) {
  return bytes.compare(offset, 4, kFrameMagic, 4) == 0;
}

struct FrameView {
  bool header_present{false};
  bool payload_present{false};
  bool checksum_matches{false};
  StoreRecordKind kind{StoreRecordKind::SiteDescriptor};
  std::uint32_t payload_length{0};
  Epoch epoch{};
  SequenceNumber sequence{};
  Timestamp at{};
  std::string payload;
};

FrameView inspect_frame(const std::string& bytes, std::size_t offset) {
  FrameView view;
  if (bytes.size() < offset + kFrameHeaderSize) return view;
  if (!frame_magic_matches(bytes, offset)) return view;
  view.header_present = true;
  view.kind = static_cast<StoreRecordKind>(static_cast<unsigned char>(bytes[offset + 4]));
  view.payload_length = read_u32(bytes, offset + 6);
  view.epoch = Epoch{read_u64(bytes, offset + 14)};
  view.sequence = SequenceNumber{read_u64(bytes, offset + 22)};
  view.at = Timestamp{static_cast<Millis>(read_u64(bytes, offset + 30))};
  if (view.payload_length > limits::kMaxStoreRecordBytes) return view;
  if (bytes.size() < offset + kFrameHeaderSize + view.payload_length) return view;
  view.payload_present = true;
  view.payload = bytes.substr(offset + kFrameHeaderSize, view.payload_length);
  const std::uint32_t stored_crc = read_u32(bytes, offset + 10);
  const std::uint32_t computed = crc32c(view.payload.data(), view.payload.size());
  view.checksum_matches = stored_crc == computed;
  return view;
}

bool any_valid_frame_after(const std::string& bytes, std::size_t offset) {
  if (bytes.size() < kFrameHeaderSize) return false;
  for (std::size_t probe = offset + 1; probe + kFrameHeaderSize <= bytes.size(); ++probe) {
    if (!frame_magic_matches(bytes, probe)) continue;
    const FrameView view = inspect_frame(bytes, probe);
    if (view.header_present && view.payload_present && view.checksum_matches) return true;
  }
  return false;
}

Status invalid(std::string message, std::string detail = {}) {
  return Status::failure(ErrorCode::InvalidArgument, std::move(message), std::move(detail));
}

Digest digest_of(const std::string& bytes) { return Sha256::hash(bytes); }

// The manifest carries its own digest so a hand-edited or truncated manifest is detected rather
// than obeyed.
Status verify_manifest_digest(const JsonValue& parsed) {
  const JsonValue* digest = parsed.find("digest");
  if (digest == nullptr || !digest->is_string()) {
    return Status::failure(ErrorCode::MalformedInput, "store manifest has no digest");
  }
  JsonValue::Object fields;
  for (const auto& field : parsed.object_items()) {
    if (field.first == "digest") continue;
    fields.push_back(field);
  }
  const JsonValue without_digest = JsonValue::object(std::move(fields));
  if (digest_of(without_digest.dump(true)).to_hex() != digest->as_string()) {
    return Status::failure(ErrorCode::IntegrityFailure,
                           "store manifest digest does not match content");
  }
  return Status::success();
}

}  // namespace

const char* store_record_kind_name(StoreRecordKind kind) noexcept {
  switch (kind) {
    case StoreRecordKind::SiteDescriptor: return "site-descriptor";
    case StoreRecordKind::BundleAccepted: return "bundle-accepted";
    case StoreRecordKind::BundleActivated: return "bundle-activated";
    case StoreRecordKind::LocalBundleRegistered: return "local-bundle-registered";
    case StoreRecordKind::OverrideRegistered: return "override-registered";
    case StoreRecordKind::OverrideRevoked: return "override-revoked";
    case StoreRecordKind::ReceiptAppended: return "receipt-appended";
    case StoreRecordKind::ConflictRecorded: return "conflict-recorded";
    case StoreRecordKind::RevocationApplied: return "revocation-applied";
    case StoreRecordKind::AuthorityGrantAdded: return "authority-grant-added";
    case StoreRecordKind::AuthorityEpochAdvanced: return "authority-epoch-advanced";
    case StoreRecordKind::CapabilitySnapshotUpdated: return "capability-snapshot-updated";
    case StoreRecordKind::GenerationFenced: return "generation-fenced";
    case StoreRecordKind::CapabilityCatalogUpdated: return "capability-catalog-updated";
  }
  return "unknown";
}

Result<StoreRecordKind> store_record_kind_from_name(std::string_view name) {
  for (std::uint8_t raw = 1; raw <= 14; ++raw) {
    const auto kind = static_cast<StoreRecordKind>(raw);
    if (name == store_record_kind_name(kind)) return Result<StoreRecordKind>::success(kind);
  }
  return Result<StoreRecordKind>::failure(ErrorCode::MalformedInput, "unknown store record kind",
                                          escape_preview(name));
}

const char* recovery_outcome_name(RecoveryOutcome outcome) noexcept {
  switch (outcome) {
    case RecoveryOutcome::CreatedNew: return "created-new";
    case RecoveryOutcome::Clean: return "clean";
    case RecoveryOutcome::TornTailDiscarded: return "torn-tail-discarded";
    case RecoveryOutcome::InteriorCorruption: return "interior-corruption";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------------------
// DurableStore
// ---------------------------------------------------------------------------------------

DurableStore::~DurableStore() {
  if (open_) {
    auto status = close();
    (void)status;
  }
}

DurableStore::DurableStore(DurableStore&& other) noexcept { *this = std::move(other); }

DurableStore& DurableStore::operator=(DurableStore&& other) noexcept {
  if (this == &other) return *this;
  std::scoped_lock lock(mutex_, other.mutex_);
  directory_ = std::move(other.directory_);
  wal_name_ = std::move(other.wal_name_);
  snapshot_name_ = std::move(other.snapshot_name_);
  identity_ = other.identity_;
  report_ = std::move(other.report_);
  epoch_ = other.epoch_;
  last_sequence_ = other.last_sequence_;
  reopen_count_ = other.reopen_count_;
  snapshot_sequence_ = other.snapshot_sequence_;
  manifest_updated_at_ = other.manifest_updated_at_;
  records_ = std::move(other.records_);
  snapshot_payload_ = std::move(other.snapshot_payload_);
  open_ = other.open_;
  writable_ = other.writable_;
  load_failure_ = other.load_failure_;
  other.open_ = false;
  other.writable_ = false;
  return *this;
}

Status DurableStore::publish_manifest(std::uint64_t snapshot_sequence, const std::string& snapshot_name,
                                      const std::string& wal_name, Timestamp at) {
  JsonValue manifest = JsonValue::object({
      {"format_version", JsonValue::integer(static_cast<std::int64_t>(identity_.format_version))},
      {"store_id", JsonValue::text(identity_.id.to_string())},
      {"federation", JsonValue::text(identity_.federation.to_string())},
      {"member", JsonValue::text(identity_.member.to_string())},
      {"site", JsonValue::text(identity_.site.to_string())},
      {"created_at", JsonValue::integer(identity_.created_at.ms)},
      {"epoch", JsonValue::integer(static_cast<std::int64_t>(epoch_.value))},
      {"sequence", JsonValue::integer(static_cast<std::int64_t>(last_sequence_.value))},
      {"reopen_count", JsonValue::integer(static_cast<std::int64_t>(reopen_count_))},
      {"updated_at", JsonValue::integer(at.ms)},
      {"snapshot_sequence", JsonValue::integer(static_cast<std::int64_t>(snapshot_sequence))},
      {"snapshot", JsonValue::text(snapshot_name)},
      {"wal", JsonValue::text(wal_name)},
  });
  // The manifest carries its own digest so a hand-edited identity is detected rather than obeyed.
  const std::string canonical = manifest.dump(true);
  manifest.set_field("digest", JsonValue::text(digest_of(canonical).to_hex()));
  const Status status = platform::write_file_atomic(directory_ / manifest_name(), manifest.dump(true));
  if (!status.ok()) return status;
  snapshot_sequence_ = snapshot_sequence;
  manifest_updated_at_ = at;
  return Status::success();
}

Status DurableStore::load_manifest(const std::string& text) {
  auto parsed = JsonValue::parse(text);
  if (!parsed) return Status::failure(parsed.error);
  if (!parsed->is_object()) return invalid("store manifest is not a json object");
  auto format = parsed->require_int_in_range("format_version", 1, 1000);
  if (!format) return Status::failure(format.error);
  if (static_cast<std::uint32_t>(*format) != kStoreFormatVersion) {
    return Status::failure(ErrorCode::UnsupportedFormat, "unsupported store format version",
                           std::to_string(*format));
  }
  const Status digest_status = verify_manifest_digest(*parsed);
  if (!digest_status.ok()) return digest_status;
  auto store_id = parsed->require_string("store_id");
  if (!store_id) return Status::failure(store_id.error);
  auto parsed_store = StoreId::parse(*store_id);
  if (!parsed_store) return Status::failure(parsed_store.error);
  auto federation = parsed->require_string("federation");
  if (!federation) return Status::failure(federation.error);
  auto parsed_federation = FederationId::parse(*federation);
  if (!parsed_federation) return Status::failure(parsed_federation.error);
  auto member = parsed->require_string("member");
  if (!member) return Status::failure(member.error);
  auto parsed_member = MemberId::parse(*member);
  if (!parsed_member) return Status::failure(parsed_member.error);
  auto site = parsed->require_string("site");
  if (!site) return Status::failure(site.error);
  auto parsed_site = SiteId::parse(*site);
  if (!parsed_site) return Status::failure(parsed_site.error);
  auto created_at = parsed->require_int("created_at");
  if (!created_at) return Status::failure(created_at.error);
  auto epoch = parsed->require_int_in_range("epoch", 0, INT64_MAX);
  if (!epoch) return Status::failure(epoch.error);
  auto sequence = parsed->require_int_in_range("sequence", 0, INT64_MAX);
  if (!sequence) return Status::failure(sequence.error);
  auto reopen_count = parsed->require_int_in_range("reopen_count", 0, INT64_MAX);
  if (!reopen_count) return Status::failure(reopen_count.error);
  auto snapshot_sequence = parsed->require_int_in_range("snapshot_sequence", 0, INT64_MAX);
  if (!snapshot_sequence) return Status::failure(snapshot_sequence.error);
  auto snapshot = parsed->require_string("snapshot");
  if (!snapshot) return Status::failure(snapshot.error);
  auto wal = parsed->require_string("wal");
  if (!wal) return Status::failure(wal.error);

  identity_.id = *parsed_store;
  identity_.federation = *parsed_federation;
  identity_.member = *parsed_member;
  identity_.site = *parsed_site;
  identity_.created_at = Timestamp{*created_at};
  identity_.format_version = static_cast<std::uint32_t>(*format);
  epoch_ = Epoch{static_cast<std::uint64_t>(*epoch)};
  last_sequence_ = SequenceNumber{static_cast<std::uint64_t>(*sequence)};
  reopen_count_ = static_cast<std::uint64_t>(*reopen_count);
  snapshot_sequence_ = static_cast<std::uint64_t>(*snapshot_sequence);

  // File names come from the manifest, so they are validated as safe single components before any
  // path is constructed. A manifest that tries to escape its directory is refused.
  if (!snapshot->empty() && !is_safe_filename_component(*snapshot)) {
    return invalid("store manifest names an unsafe snapshot file", escape_preview(*snapshot));
  }
  if (!is_safe_filename_component(*wal)) {
    return invalid("store manifest names an unsafe log file", escape_preview(*wal));
  }
  snapshot_name_ = snapshot->empty() ? std::filesystem::path() : std::filesystem::path(*snapshot);
  wal_name_ = std::filesystem::path(*wal);
  if (!platform::is_within_directory(directory_, directory_ / wal_name_)) {
    return invalid("store log path escapes the store directory", wal_name_.string());
  }
  if (!snapshot_name_.empty() &&
      !platform::is_within_directory(directory_, directory_ / snapshot_name_)) {
    return invalid("store snapshot path escapes the store directory", snapshot_name_.string());
  }
  return Status::success();
}

Status DurableStore::load_snapshot(std::string& snapshot_payload) {
  snapshot_payload.clear();
  if (snapshot_name_.empty()) return Status::success();
  auto text = platform::read_file(directory_ / snapshot_name_, limits::kMaxWireMessageBytes);
  if (!text) return Status::failure(text.error);
  auto parsed = JsonValue::parse(*text);
  if (!parsed) return Status::failure(parsed.error);
  auto format = parsed->require_int_in_range("format_version", 1, 1000);
  if (!format) return Status::failure(format.error);
  if (static_cast<std::uint32_t>(*format) != kStoreFormatVersion) {
    return Status::failure(ErrorCode::UnsupportedFormat, "unsupported snapshot format version", {});
  }
  auto store_id = parsed->require_string("store_id");
  if (!store_id) return Status::failure(store_id.error);
  if (*store_id != identity_.id.to_string()) {
    return Status::failure(ErrorCode::Divergent, "snapshot belongs to another store", *store_id);
  }
  auto sequence = parsed->require_int_in_range("sequence", 0, INT64_MAX);
  if (!sequence) return Status::failure(sequence.error);
  if (static_cast<std::uint64_t>(*sequence) != snapshot_sequence_) {
    return Status::failure(ErrorCode::Divergent, "snapshot sequence does not match the manifest",
                           std::to_string(*sequence));
  }
  auto digest = parsed->require_string("digest");
  if (!digest) return Status::failure(digest.error);
  auto payload = parsed->require_string("payload");
  if (!payload) return Status::failure(payload.error);
  if (digest_of(*payload).to_hex() != *digest) {
    return Status::failure(ErrorCode::IntegrityFailure, "snapshot digest does not match its payload");
  }
  snapshot_payload = *payload;
  return Status::success();
}

void DurableStore::walk_log(const std::string& bytes) {
  report_.log_bytes = bytes.size();
  // A log always continues the active snapshot: sequence snapshot_sequence + 1, then contiguous.
  // The manifest's reported sequence is the last committed sequence and is not the log's origin.
  SequenceNumber expected{snapshot_sequence_};
  auto next_expected = expected.next();
  if (next_expected) expected = *next_expected;
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const FrameView view = inspect_frame(bytes, offset);
    if (!view.header_present) {
      if (any_valid_frame_after(bytes, offset)) {
        report_.outcome = RecoveryOutcome::InteriorCorruption;
        report_.writable = false;
        report_.bytes_discarded = bytes.size() - offset;
        report_.detail = "log contains a damaged record followed by valid records; refusing to truncate";
      } else {
        report_.outcome = report_.outcome == RecoveryOutcome::CreatedNew
                              ? RecoveryOutcome::CreatedNew
                              : RecoveryOutcome::TornTailDiscarded;
        report_.bytes_discarded = bytes.size() - offset;
        report_.detail = "trailing bytes do not form a complete record";
      }
      break;
    }
    if (!view.payload_present) {
      report_.outcome = RecoveryOutcome::TornTailDiscarded;
      report_.bytes_discarded = bytes.size() - offset;
      report_.detail = "final record was not written completely";
      break;
    }
    if (!view.checksum_matches) {
      if (any_valid_frame_after(bytes, offset + kFrameHeaderSize + view.payload_length)) {
        report_.outcome = RecoveryOutcome::InteriorCorruption;
        report_.writable = false;
        report_.bytes_discarded = bytes.size() - offset;
        report_.detail = "record checksum mismatch with valid records after it";
      } else {
        report_.outcome = RecoveryOutcome::TornTailDiscarded;
        report_.bytes_discarded = bytes.size() - offset;
        report_.detail = "final record failed its checksum";
      }
      break;
    }
    StoreRecord record;
    record.kind = view.kind;
    record.writer_epoch = view.epoch;
    record.sequence = view.sequence;
    record.at = view.at;
    record.payload = view.payload;
    record.payload_digest = digest_of(view.payload);
    if (view.sequence.value == 0 || view.sequence != expected) {
      report_.outcome = RecoveryOutcome::InteriorCorruption;
      report_.writable = false;
      report_.bytes_discarded = bytes.size() - offset;
      report_.detail = "log is not contiguous at record " + std::to_string(view.sequence.value) +
                       " (expected " + std::to_string(expected.value) + ")";
      break;
    }
    last_sequence_ = view.sequence;
    auto following = view.sequence.next();
    if (following) expected = *following;
    records_.push_back(std::move(record));
    ++report_.records_replayed;
    offset += kFrameHeaderSize + view.payload_length;
    if (report_.records_replayed > limits::kMaxReceiptsPerSite * 4) {
      report_.outcome = RecoveryOutcome::InteriorCorruption;
      report_.writable = false;
      report_.detail = "log contains more records than this boundary will replay";
      break;
    }
  }
  if (report_.outcome == RecoveryOutcome::Clean && offset < bytes.size()) {
    report_.outcome = RecoveryOutcome::TornTailDiscarded;
    report_.bytes_discarded = bytes.size() - offset;
  }
}

Result<DurableStore> DurableStore::open(const StoreOpenOptions& options) {
  DurableStore store;
  store.directory_ = options.directory;
  auto directory_status = platform::ensure_directory(options.directory);
  if (!directory_status.ok()) return Result<DurableStore>::failure(directory_status.error);
  if (!platform::is_within_directory(options.directory, options.directory)) {
    return Result<DurableStore>::failure(ErrorCode::InvalidArgument,
                                         "store directory is not addressable", options.directory.string());
  }

  const std::filesystem::path manifest_path = options.directory / manifest_name();
  const bool manifest_exists = platform::path_exists(manifest_path);
  const Timestamp now = options.identity.created_at.ms == 0 ? Timestamp{platform::system_now_millis()}
                                                            : options.identity.created_at;
  if (!manifest_exists) {
    if (!options.create_if_missing) {
      return Result<DurableStore>::failure(ErrorCode::NotFound, "store manifest does not exist",
                                           manifest_path.string());
    }
    IdGenerator generator(static_cast<std::uint64_t>(platform::system_now_millis()));
    store.identity_ = options.identity;
    if (store.identity_.id.is_nil()) {
      store.identity_.id.value = generator.next();
    }
    if (store.identity_.federation.is_nil() || store.identity_.member.is_nil() ||
        store.identity_.site.is_nil()) {
      return Result<DurableStore>::failure(
          ErrorCode::InvalidArgument,
          "a new store needs the federation, member and site it belongs to");
    }
    store.identity_.created_at = now;
    store.identity_.format_version = kStoreFormatVersion;
    store.epoch_ = Epoch{};
    store.last_sequence_ = SequenceNumber{};
    store.reopen_count_ = 0;
    store.snapshot_sequence_ = 0;
    store.snapshot_name_ = std::filesystem::path();
    store.wal_name_ = std::filesystem::path(wal_file_name(1));
    store.report_.outcome = RecoveryOutcome::CreatedNew;
    store.report_.detail = "store created";
    const Status wal_status =
        platform::append_file_durable(options.directory / store.wal_name_, std::string_view());
    if (!wal_status.ok()) return Result<DurableStore>::failure(wal_status.error);
    const Status manifest_status = store.publish_manifest(0, std::string(), store.wal_name_.string(), now);
    if (!manifest_status.ok()) return Result<DurableStore>::failure(manifest_status.error);
  } else {
    auto text = platform::read_file(manifest_path, 1024 * 1024);
    if (!text) return Result<DurableStore>::failure(text.error);
    const Status status = store.load_manifest(*text);
    if (!status.ok()) return Result<DurableStore>::failure(status.error);
    const Status snapshot_status = store.load_snapshot(store.snapshot_payload_);
    if (!snapshot_status.ok()) return Result<DurableStore>::failure(snapshot_status.error);
    auto log = platform::read_file(options.directory / store.wal_name_, options.max_log_bytes);
    if (!log) {
      if (log.error.code == ErrorCode::TooLarge) {
        return Result<DurableStore>::failure(ErrorCode::TooLarge, "write-ahead log exceeds the limit",
                                             store.wal_name_.string());
      }
      return Result<DurableStore>::failure(log.error);
    }
    store.report_.outcome = RecoveryOutcome::Clean;
    store.last_sequence_ = SequenceNumber{store.snapshot_sequence_};
    store.walk_log(*log);
    if (store.report_.outcome == RecoveryOutcome::TornTailDiscarded && store.report_.writable) {
      const std::uint64_t keep = static_cast<std::uint64_t>(log->size()) - store.report_.bytes_discarded;
      const Status truncate_status = platform::truncate_file(options.directory / store.wal_name_, keep);
      if (!truncate_status.ok()) return Result<DurableStore>::failure(truncate_status.error);
      store.report_.notes.push_back("discarded " + std::to_string(store.report_.bytes_discarded) +
                                    " trailing bytes and truncated the log to " +
                                    std::to_string(keep) + " bytes");
    }
    if (store.report_.outcome == RecoveryOutcome::InteriorCorruption) {
      store.writable_ = false;
      store.report_.notes.push_back(
          "the store is opened read-only: interior corruption must be adjudicated, not truncated away");
    }
  }

  if (store.writable_) {
    // Fencing barrier: every open advances the epoch, so writers from a previous incarnation are
    // refused instead of publishing into a state they no longer own.
    auto next_epoch = store.epoch_.next();
    if (!next_epoch) return Result<DurableStore>::failure(next_epoch.error);
    store.epoch_ = *next_epoch;
    ++store.reopen_count_;
    const Status manifest_status =
        store.publish_manifest(store.snapshot_sequence_, store.snapshot_name_.string(),
                               store.wal_name_.string(), Timestamp{platform::system_now_millis()});
    if (!manifest_status.ok()) return Result<DurableStore>::failure(manifest_status.error);
  }
  store.report_.opened_epoch = store.epoch_;
  store.report_.last_sequence = store.last_sequence_;
  store.report_.reopen_count = store.reopen_count_;
  store.open_ = true;
  return Result<DurableStore>::success(std::move(store));
}
Status DurableStore::append(Epoch writer_epoch, StoreRecordKind kind, std::string payload, Timestamp at) {
  std::lock_guard<std::mutex> lock(mutex_);
  return append_locked(writer_epoch, kind, payload, at);
}

Status DurableStore::append(StoreRecordKind kind, std::string payload, Timestamp at) {
  std::lock_guard<std::mutex> lock(mutex_);
  return append_locked(epoch_, kind, payload, at);
}

Status DurableStore::verify_ownership_locked() const {
  auto text = platform::read_file(directory_ / manifest_name(), 1024 * 1024);
  if (!text) return Status::failure(text.error);
  auto parsed = JsonValue::parse(*text);
  if (!parsed) return Status::failure(parsed.error);
  const Status digest_status = verify_manifest_digest(*parsed);
  if (!digest_status.ok()) return digest_status;
  auto epoch = parsed->require_int_in_range("epoch", 0, INT64_MAX);
  if (!epoch) return Status::failure(epoch.error);
  if (static_cast<std::uint64_t>(*epoch) != epoch_.value) {
    return Status::failure(ErrorCode::Fenced,
                           "another writer owns this store: the persisted epoch has moved on",
                           "store epoch " + std::to_string(*epoch) + ", writer epoch " +
                               std::to_string(epoch_.value));
  }
  return Status::success();
}

Status DurableStore::append_locked(Epoch writer_epoch, StoreRecordKind kind,
                                   const std::string& payload, Timestamp at) {
  if (!open_) return Status::failure(ErrorCode::InvalidState, "store is not open");
  if (!writable_) {
    return Status::failure(ErrorCode::InteriorCorruption,
                           "store is read-only because its log contains interior corruption",
                           report_.detail);
  }
  if (writer_epoch != epoch_) {
    return Status::failure(ErrorCode::Fenced,
                           "writer epoch is not the current store epoch: stale writers are refused",
                           "writer " + std::to_string(writer_epoch.value) + " store " +
                               std::to_string(epoch_.value));
  }
  if (payload.size() > limits::kMaxStoreRecordBytes) {
    return Status::failure(ErrorCode::TooLarge, "record payload exceeds the record limit",
                           std::to_string(payload.size()));
  }
  const Status ownership = verify_ownership_locked();
  if (!ownership.ok()) return ownership;
  auto next = last_sequence_.next();
  if (!next) return Status::failure(next.error);

  std::string frame;
  frame.reserve(kFrameHeaderSize + payload.size());
  frame.append(kFrameMagic, 4);
  frame.push_back(static_cast<char>(static_cast<std::uint8_t>(kind)));
  frame.push_back(static_cast<char>(0));
  put_u32(frame, static_cast<std::uint32_t>(payload.size()));
  put_u32(frame, crc32c(payload.data(), payload.size()));
  put_u64(frame, epoch_.value);
  put_u64(frame, next->value);
  put_u64(frame, static_cast<std::uint64_t>(at.ms));
  frame.append(payload);

  const Status status = platform::append_file_durable(directory_ / wal_name_, frame);
  if (!status.ok()) return status;

  StoreRecord record;
  record.kind = kind;
  record.writer_epoch = epoch_;
  record.sequence = *next;
  record.at = at;
  record.payload = payload;
  record.payload_digest = digest_of(payload);
  records_.push_back(std::move(record));
  last_sequence_ = *next;
  return Status::success();
}

std::vector<StoreRecord> DurableStore::records() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return records_;
}

Status DurableStore::compact(std::string snapshot_payload, Timestamp at) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!open_) return Status::failure(ErrorCode::InvalidState, "store is not open");
  if (!writable_) {
    return Status::failure(ErrorCode::InteriorCorruption,
                           "refusing to compact a store with interior corruption", report_.detail);
  }
  if (snapshot_payload.size() > limits::kMaxWireMessageBytes) {
    return Status::failure(ErrorCode::TooLarge, "snapshot payload exceeds the limit",
                           std::to_string(snapshot_payload.size()));
  }
  const Status ownership = verify_ownership_locked();
  if (!ownership.ok()) return ownership;
  const std::uint64_t covered_sequence = last_sequence_.value;
  const std::filesystem::path new_snapshot = snapshot_file_name(covered_sequence);
  const std::filesystem::path new_wal = wal_file_name(covered_sequence + 1);

  JsonValue snapshot = JsonValue::object({
      {"format_version", JsonValue::integer(static_cast<std::int64_t>(kStoreFormatVersion))},
      {"store_id", JsonValue::text(identity_.id.to_string())},
      {"sequence", JsonValue::integer(static_cast<std::int64_t>(covered_sequence))},
      {"epoch", JsonValue::integer(static_cast<std::int64_t>(epoch_.value))},
      {"digest", JsonValue::text(digest_of(snapshot_payload).to_hex())},
      {"payload", JsonValue::text(snapshot_payload)},
  });
  const Status write_status = platform::write_file_atomic(directory_ / new_snapshot, snapshot.dump(true));
  if (!write_status.ok()) return write_status;

  // The new log exists and is durable before the manifest points at it.
  const Status wal_status = platform::append_file_durable(directory_ / new_wal, std::string_view());
  if (!wal_status.ok()) return wal_status;

  const std::filesystem::path previous_wal = wal_name_;
  const std::filesystem::path previous_snapshot = snapshot_name_;
  const Status manifest_status =
      publish_manifest(covered_sequence, new_snapshot.string(), new_wal.string(), at);
  if (!manifest_status.ok()) return manifest_status;

  wal_name_ = new_wal;
  snapshot_name_ = new_snapshot;
  snapshot_payload_ = snapshot_payload;
  report_.notes.push_back("compacted state through sequence " + std::to_string(covered_sequence));

  // Superseded files are removed only after the manifest that replaces them is durable.
  if (!previous_wal.empty() && previous_wal != new_wal) {
    const Status status = platform::remove_file_if_present(directory_ / previous_wal);
    if (!status.ok()) report_.notes.push_back("could not remove superseded log: " + status.error.message);
  }
  if (!previous_snapshot.empty() && previous_snapshot != new_snapshot) {
    const Status status = platform::remove_file_if_present(directory_ / previous_snapshot);
    if (!status.ok()) {
      report_.notes.push_back("could not remove superseded snapshot: " + status.error.message);
    }
  }
  return Status::success();
}

Status DurableStore::close() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!open_) return Status::success();
  // Every append flushed before returning, so closing is bookkeeping rather than a commit point.
  open_ = false;
  return Status::success();
}

// ---------------------------------------------------------------------------------------
// Typed site state
// ---------------------------------------------------------------------------------------

const PolicyBundle* PersistedSiteState::find_bundle(PolicyBundleId id) const noexcept {
  for (const PolicyBundle& bundle : accepted_bundles) {
    if (bundle.id == id) return &bundle;
  }
  for (const PolicyBundle& bundle : local_bundles) {
    if (bundle.id == id) return &bundle;
  }
  return nullptr;
}

const LocalOverride* PersistedSiteState::find_override(OverrideId id) const noexcept {
  for (const LocalOverride& record : overrides) {
    if (record.id == id) return &record;
  }
  return nullptr;
}

std::string encode_bundle_record(const PolicyBundle& bundle) { return bundle_to_json(bundle).dump(true); }
std::string encode_override_record(const LocalOverride& record) { return override_to_json(record).dump(true); }
std::string encode_receipt_record(const Receipt& receipt) { return receipt_to_json(receipt).dump(true); }
std::string encode_conflict_record(const ConflictRecord& record) { return conflict_to_json(record).dump(true); }
std::string encode_revocation_record(const RevocationRecord& record) {
  return revocation_to_json(record).dump(true);
}
std::string encode_grant_record(const AuthorityGrant& grant) { return grant_to_json(grant).dump(true); }
std::string encode_capability_record(const SiteCapabilitySnapshot& snapshot) {
  return capability_snapshot_to_json(snapshot).dump(true);
}

std::string encode_catalog_record(const CapabilityCatalog& catalog) {
  return capability_catalog_to_json(catalog).dump(true);
}

std::string encode_generation_record(Generation global_generation, Generation local_generation,
                                  Timestamp last_federation_contact) {
  return JsonValue::object({
             {"global_generation", JsonValue::integer(static_cast<std::int64_t>(global_generation.value))},
             {"local_generation", JsonValue::integer(static_cast<std::int64_t>(local_generation.value))},
             {"contact_at", JsonValue::integer(last_federation_contact.ms)},
         })
      .dump(true);
}

std::string encode_epoch_record(Epoch epoch) {
  return JsonValue::object({{"epoch", JsonValue::integer(static_cast<std::int64_t>(epoch.value))}})
      .dump(true);
}

namespace {

Result<JsonValue> parse_payload(const StoreRecord& record) {
  auto parsed = JsonValue::parse(record.payload);
  if (!parsed) {
    return Result<JsonValue>::failure(ErrorCode::IntegrityFailure, "record payload is not valid json",
                                      record.payload.substr(0, 64));
  }
  return parsed;
}

Status require_next_sequence(const PersistedSiteState& state, const StoreRecord& record) {
  if (state.applied_sequence.is_nil()) {
    // The caller replays a window that starts wherever its snapshot ended. Sequence zero is never
    // a valid record number, and contiguity is enforced from the first replayed record onwards.
    if (record.sequence.value == 0) {
      return Status::failure(ErrorCode::Reordered, "log starts at sequence zero", {});
    }
    return Status::success();
  }
  if (record.sequence.value != state.applied_sequence.value + 1) {
    return Status::failure(ErrorCode::Reordered, "log sequence is not contiguous",
                           std::to_string(record.sequence.value));
  }
  return Status::success();
}

}  // namespace

Status apply_record(PersistedSiteState& state, const StoreRecord& record, bool& applied) {
  applied = false;
  if (!state.applied_sequence.is_nil() && record.sequence.value <= state.applied_sequence.value) {
    // Replayed history: the same record delivered twice is not applied twice.
    return Status::success();
  }
  const Status sequence_status = require_next_sequence(state, record);
  if (!sequence_status.ok()) return sequence_status;
  auto payload = parse_payload(record);
  if (!payload) return Status::failure(payload.error);

  switch (record.kind) {
    case StoreRecordKind::SiteDescriptor: {
      auto store_id = payload->require_string("store_id");
      if (!store_id) return Status::failure(store_id.error);
      if (*store_id != state.identity.id.to_string()) {
        return Status::failure(ErrorCode::Divergent, "descriptor names a different store", *store_id);
      }
      break;
    }
    case StoreRecordKind::BundleAccepted:
    case StoreRecordKind::LocalBundleRegistered: {
      auto bundle = bundle_from_json(*payload);
      if (!bundle) return Status::failure(bundle.error);
      std::vector<PolicyBundle>& target = record.kind == StoreRecordKind::BundleAccepted
                                              ? state.accepted_bundles
                                              : state.local_bundles;
      for (const PolicyBundle& existing : target) {
        if (existing.id == bundle->id) {
          if (existing.integrity_digest != bundle->integrity_digest) {
            return Status::failure(ErrorCode::Divergent,
                                   "the same bundle identity was accepted with different content",
                                   bundle->id.to_string());
          }
          state.applied_sequence = record.sequence;
          return Status::success();
        }
      }
      if (record.kind == StoreRecordKind::BundleAccepted) {
        if (bundle->global_generation > state.applied_global_generation) {
          state.applied_global_generation = bundle->global_generation;
        }
      } else if (bundle->global_generation > state.local_generation) {
        state.local_generation = bundle->global_generation;
      }
      target.push_back(std::move(*bundle.value));
      break;
    }
    case StoreRecordKind::BundleActivated: {
      auto global = payload->require_int_in_range("global_generation", 0, INT64_MAX);
      if (!global) return Status::failure(global.error);
      auto local = payload->require_int_in_range("local_generation", 0, INT64_MAX);
      if (!local) return Status::failure(local.error);
      const Generation global_generation{static_cast<std::uint64_t>(*global)};
      const Generation local_generation{static_cast<std::uint64_t>(*local)};
      if (global_generation < state.applied_global_generation ||
          local_generation < state.local_generation) {
        return Status::failure(ErrorCode::StaleGeneration,
                               "activation would move a generation backwards",
                               std::to_string(global_generation.value));
      }
      state.applied_global_generation = global_generation;
      state.local_generation = local_generation;
      if (payload->contains("contact_at")) {
        auto contact = payload->require_int("contact_at");
        if (!contact) return Status::failure(contact.error);
        if (*contact > state.last_federation_contact.ms) {
          state.last_federation_contact = Timestamp{*contact};
        }
      }
      break;
    }
    case StoreRecordKind::OverrideRegistered: {
      auto override_record = override_from_json(*payload);
      if (!override_record) return Status::failure(override_record.error);
      for (const LocalOverride& existing : state.overrides) {
        if (existing.id == override_record->id) {
          if (existing.digest != override_record->digest) {
            return Status::failure(ErrorCode::Divergent,
                                   "the same override identity was registered with different content",
                                   override_record->id.to_string());
          }
          state.applied_sequence = record.sequence;
          return Status::success();
        }
      }
      if (override_record->local_generation > state.local_generation) {
        state.local_generation = override_record->local_generation;
      }
      state.overrides.push_back(std::move(*override_record.value));
      break;
    }
    case StoreRecordKind::OverrideRevoked: {
      auto id = payload->require_string("override_id");
      if (!id) return Status::failure(id.error);
      auto parsed = OverrideId::parse(*id);
      if (!parsed) return Status::failure(parsed.error);
      state.overrides.erase(std::remove_if(state.overrides.begin(), state.overrides.end(),
                                           [&](const LocalOverride& candidate) {
                                             return candidate.id == *parsed;
                                           }),
                            state.overrides.end());
      break;
    }
    case StoreRecordKind::ReceiptAppended: {
      auto receipt = receipt_from_json(*payload);
      if (!receipt) return Status::failure(receipt.error);
      for (const Receipt& existing : state.receipts) {
        if (existing.id == receipt->id) {
          state.applied_sequence = record.sequence;
          return Status::success();
        }
      }
      const SequenceNumber next = SequenceNumber{receipt->sequence.value + 1};
      if (next > state.next_receipt_sequence) state.next_receipt_sequence = next;
      state.receipts.push_back(std::move(*receipt.value));
      break;
    }
    case StoreRecordKind::ConflictRecorded: {
      auto conflict = conflict_from_json(*payload);
      if (!conflict) return Status::failure(conflict.error);
      for (const ConflictRecord& existing : state.conflicts) {
        if (existing.id == conflict->id) {
          state.applied_sequence = record.sequence;
          return Status::success();
        }
      }
      state.conflicts.push_back(std::move(*conflict.value));
      break;
    }
    case StoreRecordKind::RevocationApplied: {
      auto revocation = revocation_from_json(*payload);
      if (!revocation) return Status::failure(revocation.error);
      for (const RevocationRecord& existing : state.revocations) {
        if (existing.id == revocation->id) {
          state.applied_sequence = record.sequence;
          return Status::success();
        }
      }
      for (const RevocationRecord& existing : state.revocations) {
        if (existing.sequence == revocation->sequence) {
          return Status::failure(ErrorCode::Reordered, "two revocations share one sequence number",
                                 revocation->id.to_string());
        }
      }
      state.revocations.push_back(std::move(*revocation.value));
      break;
    }
    case StoreRecordKind::AuthorityGrantAdded: {
      auto grant = grant_from_json(*payload);
      if (!grant) return Status::failure(grant.error);
      for (const AuthorityGrant& existing : state.grants) {
        if (existing.id == grant->id) {
          if (existing.digest != grant->digest) {
            return Status::failure(ErrorCode::Divergent,
                                   "the same grant identity was added with different content",
                                   grant->id.to_string());
          }
          state.applied_sequence = record.sequence;
          return Status::success();
        }
      }
      state.grants.push_back(std::move(*grant.value));
      break;
    }
    case StoreRecordKind::AuthorityEpochAdvanced: {
      auto epoch = payload->require_int_in_range("epoch", 0, INT64_MAX);
      if (!epoch) return Status::failure(epoch.error);
      const Epoch requested{static_cast<std::uint64_t>(*epoch)};
      if (requested < state.authority_epoch) {
        return Status::failure(ErrorCode::StaleGeneration, "authority epoch would move backwards",
                               std::to_string(requested.value));
      }
      state.authority_epoch = requested;
      break;
    }
    case StoreRecordKind::CapabilitySnapshotUpdated: {
      auto snapshot = capability_snapshot_from_json(*payload);
      if (!snapshot) return Status::failure(snapshot.error);
      state.capabilities = std::move(*snapshot.value);
      state.has_capabilities = true;
      break;
    }
    case StoreRecordKind::CapabilityCatalogUpdated: {
      auto catalog = capability_catalog_from_json(*payload);
      if (!catalog) return Status::failure(catalog.error);
      state.catalog = std::move(*catalog.value);
      state.has_catalog = true;
      break;
    }
    case StoreRecordKind::GenerationFenced: {
      auto epoch = payload->require_int_in_range("epoch", 0, INT64_MAX);
      if (!epoch) return Status::failure(epoch.error);
      const Epoch marker{static_cast<std::uint64_t>(*epoch)};
      if (marker > state.authority_epoch) state.authority_epoch = marker;
      if (payload->contains("local_generation")) {
        auto local = payload->require_int_in_range("local_generation", 0, INT64_MAX);
        if (!local) return Status::failure(local.error);
        const Generation local_generation{static_cast<std::uint64_t>(*local)};
        if (local_generation > state.local_generation) state.local_generation = local_generation;
      }
      break;
    }
  }
  state.applied_sequence = record.sequence;
  applied = true;
  return Status::success();
}

Result<PersistedSiteState> replay_records(const StoreIdentity& identity,
                                          const std::vector<StoreRecord>& records) {
  PersistedSiteState state;
  state.identity = identity;
  for (const StoreRecord& record : records) {
    bool applied = false;
    const Status status = apply_record(state, record, applied);
    if (!status.ok()) {
      return Result<PersistedSiteState>::failure(status.error);
    }
  }
  return Result<PersistedSiteState>::success(std::move(state));
}

JsonValue site_state_to_json(const PersistedSiteState& state) {
  JsonValue::Array accepted;
  for (const PolicyBundle& bundle : state.accepted_bundles) accepted.push_back(bundle_to_json(bundle));
  JsonValue::Array local;
  for (const PolicyBundle& bundle : state.local_bundles) local.push_back(bundle_to_json(bundle));
  JsonValue::Array overrides;
  for (const LocalOverride& record : state.overrides) overrides.push_back(override_to_json(record));
  JsonValue::Array receipts;
  for (const Receipt& receipt : state.receipts) receipts.push_back(receipt_to_json(receipt));
  JsonValue::Array conflicts;
  for (const ConflictRecord& record : state.conflicts) conflicts.push_back(conflict_to_json(record));
  JsonValue::Array revocations;
  for (const RevocationRecord& record : state.revocations) revocations.push_back(revocation_to_json(record));
  JsonValue::Array grants;
  for (const AuthorityGrant& grant : state.grants) grants.push_back(grant_to_json(grant));
  return JsonValue::object({
      {"format_version", JsonValue::integer(static_cast<std::int64_t>(kStoreFormatVersion))},
      {"store_id", JsonValue::text(state.identity.id.to_string())},
      {"federation", JsonValue::text(state.identity.federation.to_string())},
      {"member", JsonValue::text(state.identity.member.to_string())},
      {"site", JsonValue::text(state.identity.site.to_string())},
      {"applied_sequence", JsonValue::integer(static_cast<std::int64_t>(state.applied_sequence.value))},
      {"applied_global_generation",
       JsonValue::integer(static_cast<std::int64_t>(state.applied_global_generation.value))},
      {"local_generation", JsonValue::integer(static_cast<std::int64_t>(state.local_generation.value))},
      {"next_receipt_sequence", JsonValue::integer(static_cast<std::int64_t>(state.next_receipt_sequence.value))},
      {"authority_epoch", JsonValue::integer(static_cast<std::int64_t>(state.authority_epoch.value))},
      {"last_federation_contact",
       JsonValue::integer(state.last_federation_contact.ms)},
      {"has_capabilities", JsonValue::boolean(state.has_capabilities)},
      {"capabilities", capability_snapshot_to_json(state.capabilities)},
      {"has_catalog", JsonValue::boolean(state.has_catalog)},
      {"catalog", capability_catalog_to_json(state.catalog)},
      {"accepted_bundles", JsonValue::array(std::move(accepted))},
      {"local_bundles", JsonValue::array(std::move(local))},
      {"overrides", JsonValue::array(std::move(overrides))},
      {"receipts", JsonValue::array(std::move(receipts))},
      {"conflicts", JsonValue::array(std::move(conflicts))},
      {"revocations", JsonValue::array(std::move(revocations))},
      {"grants", JsonValue::array(std::move(grants))},
  });
}

Result<PersistedSiteState> site_state_from_json(const JsonValue& value) {
  PersistedSiteState state;
  auto store_id = value.require_string("store_id");
  if (!store_id) return Result<PersistedSiteState>::failure(store_id.error);
  auto parsed_store = StoreId::parse(*store_id);
  if (!parsed_store) return Result<PersistedSiteState>::failure(parsed_store.error);
  state.identity.id = *parsed_store;
  auto federation = value.require_string("federation");
  if (!federation) return Result<PersistedSiteState>::failure(federation.error);
  auto parsed_federation = FederationId::parse(*federation);
  if (!parsed_federation) return Result<PersistedSiteState>::failure(parsed_federation.error);
  state.identity.federation = *parsed_federation;
  auto member = value.require_string("member");
  if (!member) return Result<PersistedSiteState>::failure(member.error);
  auto parsed_member = MemberId::parse(*member);
  if (!parsed_member) return Result<PersistedSiteState>::failure(parsed_member.error);
  state.identity.member = *parsed_member;
  auto site = value.require_string("site");
  if (!site) return Result<PersistedSiteState>::failure(site.error);
  auto parsed_site = SiteId::parse(*site);
  if (!parsed_site) return Result<PersistedSiteState>::failure(parsed_site.error);
  state.identity.site = *parsed_site;
  auto applied = value.require_int_in_range("applied_sequence", 0, INT64_MAX);
  if (!applied) return Result<PersistedSiteState>::failure(applied.error);
  state.applied_sequence = SequenceNumber{static_cast<std::uint64_t>(*applied)};
  auto global = value.require_int_in_range("applied_global_generation", 0, INT64_MAX);
  if (!global) return Result<PersistedSiteState>::failure(global.error);
  state.applied_global_generation = Generation{static_cast<std::uint64_t>(*global)};
  auto local = value.require_int_in_range("local_generation", 0, INT64_MAX);
  if (!local) return Result<PersistedSiteState>::failure(local.error);
  state.local_generation = Generation{static_cast<std::uint64_t>(*local)};
  auto next_receipt = value.require_int_in_range("next_receipt_sequence", 0, INT64_MAX);
  if (!next_receipt) return Result<PersistedSiteState>::failure(next_receipt.error);
  state.next_receipt_sequence = SequenceNumber{static_cast<std::uint64_t>(*next_receipt)};
  auto epoch = value.require_int_in_range("authority_epoch", 0, INT64_MAX);
  if (!epoch) return Result<PersistedSiteState>::failure(epoch.error);
  state.authority_epoch = Epoch{static_cast<std::uint64_t>(*epoch)};
  if (value.contains("last_federation_contact")) {
    auto contact = value.require_int("last_federation_contact");
    if (!contact) return Result<PersistedSiteState>::failure(contact.error);
    state.last_federation_contact = Timestamp{*contact};
  }
  auto has_capabilities = value.require_bool("has_capabilities");
  if (!has_capabilities) return Result<PersistedSiteState>::failure(has_capabilities.error);
  state.has_capabilities = *has_capabilities;
  auto capabilities = value.require_object("capabilities");
  if (!capabilities) return Result<PersistedSiteState>::failure(capabilities.error);
  auto parsed_capabilities = capability_snapshot_from_json(**capabilities);
  if (!parsed_capabilities) return Result<PersistedSiteState>::failure(parsed_capabilities.error);
  state.capabilities = std::move(*parsed_capabilities.value);
  auto has_catalog = value.require_bool("has_catalog");
  if (!has_catalog) return Result<PersistedSiteState>::failure(has_catalog.error);
  state.has_catalog = *has_catalog;
  auto catalog = value.require_object("catalog");
  if (!catalog) return Result<PersistedSiteState>::failure(catalog.error);
  auto parsed_catalog = capability_catalog_from_json(**catalog);
  if (!parsed_catalog) return Result<PersistedSiteState>::failure(parsed_catalog.error);
  state.catalog = std::move(*parsed_catalog.value);

  const auto read_array = [&](const char* key, auto&& apply_one) -> Status {
    auto items = value.require_array(key);
    if (!items) return Status::failure(items.error);
    for (const JsonValue& item : (*items)->array_items()) {
      const Status status = apply_one(item);
      if (!status.ok()) return status;
    }
    return Status::success();
  };
  Status status = read_array("accepted_bundles", [&](const JsonValue& item) {
    auto parsed = bundle_from_json(item);
    if (!parsed) return Status::failure(parsed.error);
    state.accepted_bundles.push_back(std::move(*parsed.value));
    return Status::success();
  });
  if (!status.ok()) return Result<PersistedSiteState>::failure(status.error);
  status = read_array("local_bundles", [&](const JsonValue& item) {
    auto parsed = bundle_from_json(item);
    if (!parsed) return Status::failure(parsed.error);
    state.local_bundles.push_back(std::move(*parsed.value));
    return Status::success();
  });
  if (!status.ok()) return Result<PersistedSiteState>::failure(status.error);
  status = read_array("overrides", [&](const JsonValue& item) {
    auto parsed = override_from_json(item);
    if (!parsed) return Status::failure(parsed.error);
    state.overrides.push_back(std::move(*parsed.value));
    return Status::success();
  });
  if (!status.ok()) return Result<PersistedSiteState>::failure(status.error);
  status = read_array("receipts", [&](const JsonValue& item) {
    auto parsed = receipt_from_json(item);
    if (!parsed) return Status::failure(parsed.error);
    state.receipts.push_back(std::move(*parsed.value));
    return Status::success();
  });
  if (!status.ok()) return Result<PersistedSiteState>::failure(status.error);
  status = read_array("conflicts", [&](const JsonValue& item) {
    auto parsed = conflict_from_json(item);
    if (!parsed) return Status::failure(parsed.error);
    state.conflicts.push_back(std::move(*parsed.value));
    return Status::success();
  });
  if (!status.ok()) return Result<PersistedSiteState>::failure(status.error);
  status = read_array("revocations", [&](const JsonValue& item) {
    auto parsed = revocation_from_json(item);
    if (!parsed) return Status::failure(parsed.error);
    state.revocations.push_back(std::move(*parsed.value));
    return Status::success();
  });
  if (!status.ok()) return Result<PersistedSiteState>::failure(status.error);
  status = read_array("grants", [&](const JsonValue& item) {
    auto parsed = grant_from_json(item);
    if (!parsed) return Status::failure(parsed.error);
    state.grants.push_back(std::move(*parsed.value));
    return Status::success();
  });
  if (!status.ok()) return Result<PersistedSiteState>::failure(status.error);
  return Result<PersistedSiteState>::success(std::move(state));
}

}  // namespace gpf
