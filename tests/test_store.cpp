#include "fixtures.hpp"
#include "gpf/platform.hpp"
#include "gpf/store.hpp"
#include "test_support.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using namespace gpf;
using namespace gpf_test;

namespace {

// Every test owns a private directory under the system temporary directory and removes it when
// the test finishes, so no scratch state survives the run.
class TempStoreDirectory {
 public:
  TempStoreDirectory(const std::string& label) {
    static int counter = 0;
    ++counter;
    path_ = std::filesystem::temp_directory_path() /
            ("gpf-store-test-" + label + "-" + std::to_string(counter));
    std::error_code error;
    std::filesystem::remove_all(path_, error);
    std::filesystem::create_directories(path_, error);
  }
  ~TempStoreDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

StoreOpenOptions make_options(const std::filesystem::path& directory, std::uint64_t seed) {
  IdGenerator ids(seed);
  StoreOpenOptions options;
  options.directory = directory;
  options.identity.id.value = ids.next();
  options.identity.federation.value = ids.next();
  options.identity.member.value = ids.next();
  options.identity.site.value = ids.next();
  options.identity.created_at = at(100 * kDay);
  return options;
}

std::string read_whole_file(const std::filesystem::path& path) {
  auto text = platform::read_file(path, 64u * 1024u * 1024u);
  return text.ok() ? *text : std::string();
}

void write_whole_file(const std::filesystem::path& path, const std::string& content) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string wal_of(const std::filesystem::path& directory) {
  auto files = platform::list_regular_files(directory);
  if (!files.ok()) return {};
  for (const std::string& name : *files) {
    if (name.rfind("wal-", 0) == 0) return name;
  }
  return {};
}

}  // namespace

GPF_TEST(store, create_append_close_reopen_replays_state) {
  TempStoreDirectory directory("round-trip");
  const StoreOpenOptions options = make_options(directory.path(), 9001);

  {
    auto store = DurableStore::open(options);
    if (!store.ok()) NOTE("open failed: " + store.error.to_string());
    REQUIRE(store.ok());
    CHECK(store->recovery().outcome == RecoveryOutcome::CreatedNew);
    CHECK_EQ(store->epoch().value, std::uint64_t{1});
    CHECK(store->is_writable());
    CHECK(store->records().empty());

    const std::string descriptor =
        "{\"store_id\":\"" + options.identity.id.to_string() + "\"}";
    REQUIRE(store->append(StoreRecordKind::SiteDescriptor, descriptor, options.identity.created_at).ok());
    REQUIRE(store->append(StoreRecordKind::CapabilitySnapshotUpdated,
                          encode_capability_record(make_snapshot(Generation{2}, {{"power.metering", SemanticVersion{2, 0, 0}}})),
                          options.identity.created_at)
                .ok());
    REQUIRE(store->append(StoreRecordKind::GenerationFenced, encode_epoch_record(Epoch{4}),
                          options.identity.created_at)
                .ok());
    CHECK_EQ(store->last_sequence().value, std::uint64_t{3});
    REQUIRE(store->close().ok());
  }

  auto reopened = DurableStore::open(options);
  if (!reopened.ok()) NOTE("reopen failed: " + reopened.error.to_string());
  REQUIRE(reopened.ok());
  CHECK(reopened->recovery().outcome == RecoveryOutcome::Clean);
  CHECK_EQ(reopened->recovery().records_replayed, std::uint64_t{3});
  CHECK_EQ(reopened->recovery().bytes_discarded, std::uint64_t{0});
  CHECK_EQ(reopened->epoch().value, std::uint64_t{2});  // reopening advances the fencing epoch
  CHECK_EQ(reopened->recovery().reopen_count, std::uint64_t{2});
  CHECK_EQ(reopened->records().size(), std::size_t{3});

  auto state = replay_records(reopened->identity(), reopened->records());
  REQUIRE(state.ok());
  CHECK(state->has_capabilities);
  CHECK_EQ(state->capabilities.catalog_generation.value, std::uint64_t{2});
  CHECK_EQ(state->authority_epoch.value, std::uint64_t{4});
  CHECK_EQ(state->applied_sequence.value, std::uint64_t{3});
}

GPF_TEST(store, reopening_fences_stale_writers) {
  TempStoreDirectory directory("fencing");
  const StoreOpenOptions options = make_options(directory.path(), 9002);

  auto first = DurableStore::open(options);
  REQUIRE(first.ok());
  const Epoch first_epoch = first->epoch();
  REQUIRE(first->append(StoreRecordKind::SiteDescriptor, "{\"writer\":\"first\"}",
                        options.identity.created_at)
              .ok());

  // A second instance (as another process would) takes ownership of the store.
  auto second = DurableStore::open(options);
  REQUIRE(second.ok());
  CHECK(second->epoch() > first_epoch);

  auto stale = first->append(StoreRecordKind::SiteDescriptor, "{\"writer\":\"stale\"}",
                             options.identity.created_at);
  CHECK(!stale.ok());
  CHECK_EQ(error_code_name(stale.error.code), std::string("fenced"));
  CHECK(first->append(first_epoch, StoreRecordKind::SiteDescriptor, "{}", options.identity.created_at)
            .ok() == false);

  // The current owner still appends normally.
  REQUIRE(second->append(StoreRecordKind::SiteDescriptor, "{\"writer\":\"second\"}",
                         options.identity.created_at)
              .ok());
  CHECK_EQ(second->last_sequence().value, std::uint64_t{2});
}

GPF_TEST(store, torn_tail_is_discarded_and_reported) {
  TempStoreDirectory directory("torn-tail");
  const StoreOpenOptions options = make_options(directory.path(), 9003);

  {
    auto store = DurableStore::open(options);
    REQUIRE(store.ok());
    for (int i = 0; i < 4; ++i) {
      REQUIRE(store->append(StoreRecordKind::SiteDescriptor,
                            "{\"record\":" + std::to_string(i) + "}", options.identity.created_at)
                  .ok());
    }
    REQUIRE(store->close().ok());
  }

  const std::string wal_name = wal_of(directory.path());
  REQUIRE(!wal_name.empty());
  const std::filesystem::path wal_path = directory.path() / wal_name;
  const std::uint64_t original_size = *platform::file_size(wal_path);

  // Append a partial final record: a complete header announcing more payload than follows.
  std::string partial;
  partial.append("GPF1", 4);
  partial.push_back(static_cast<char>(static_cast<std::uint8_t>(StoreRecordKind::ReceiptAppended)));
  partial.push_back(static_cast<char>(0));
  const std::uint32_t announced = 128;
  for (int i = 0; i < 4; ++i) partial.push_back(static_cast<char>((announced >> (i * 8)) & 0xFFu));
  for (int i = 0; i < 4; ++i) partial.push_back(static_cast<char>(0x5A));
  for (int i = 0; i < 24; ++i) partial.push_back(static_cast<char>(0));
  partial.append("partial-payload");
  REQUIRE(platform::append_file_durable(wal_path, partial).ok());

  auto reopened = DurableStore::open(options);
  if (!reopened.ok()) NOTE("reopen failed: " + reopened.error.to_string());
  REQUIRE(reopened.ok());
  CHECK(reopened->recovery().outcome == RecoveryOutcome::TornTailDiscarded);
  CHECK_EQ(reopened->recovery().records_replayed, std::uint64_t{4});
  CHECK_EQ(reopened->recovery().bytes_discarded, std::uint64_t{partial.size()});
  CHECK(reopened->is_writable());
  CHECK_EQ(*platform::file_size(wal_path), original_size);
  CHECK(!reopened->recovery().notes.empty());

  // The store keeps working after a torn tail.
  REQUIRE(reopened->append(StoreRecordKind::SiteDescriptor, "{\"record\":\"after-tear\"}",
                           options.identity.created_at)
              .ok());
  auto again = DurableStore::open(options);
  REQUIRE(again.ok());
  if (again->recovery().outcome != RecoveryOutcome::Clean) {
    NOTE("unexpected recovery outcome " + std::string(recovery_outcome_name(again->recovery().outcome)) +
         ": " + again->recovery().detail);
  }
  CHECK(again->recovery().outcome == RecoveryOutcome::Clean);
  CHECK_EQ(again->recovery().records_replayed, std::uint64_t{5});
}

GPF_TEST(store, interior_corruption_is_refused_never_truncated) {
  TempStoreDirectory directory("interior");
  const StoreOpenOptions options = make_options(directory.path(), 9004);

  {
    auto store = DurableStore::open(options);
    REQUIRE(store.ok());
    for (int i = 0; i < 5; ++i) {
      REQUIRE(store->append(StoreRecordKind::SiteDescriptor,
                            "{\"record\":" + std::to_string(i) + "}", options.identity.created_at)
                  .ok());
    }
    REQUIRE(store->close().ok());
  }

  const std::string wal_name = wal_of(directory.path());
  REQUIRE(!wal_name.empty());
  const std::filesystem::path wal_path = directory.path() / wal_name;
  std::string bytes = read_whole_file(wal_path);
  REQUIRE(bytes.size() > 120);
  // Damage the payload of the second record while leaving later records intact.
  const std::size_t damage_offset = 38 + 20 + 4;  // second record header plus part of its payload
  bytes[damage_offset] = static_cast<char>(bytes[damage_offset] ^ 0xFF);
  write_whole_file(wal_path, bytes);
  const std::uint64_t damaged_size = *platform::file_size(wal_path);

  auto reopened = DurableStore::open(options);
  REQUIRE(reopened.ok());
  CHECK(reopened->recovery().outcome == RecoveryOutcome::InteriorCorruption);
  CHECK(!reopened->is_writable());
  CHECK(!reopened->recovery().writable);
  CHECK_EQ(reopened->recovery().records_replayed, std::uint64_t{1});
  CHECK_EQ(*platform::file_size(wal_path), damaged_size);  // nothing was truncated away

  auto refused = reopened->append(StoreRecordKind::SiteDescriptor, "{}", options.identity.created_at);
  CHECK(!refused.ok());
  CHECK_EQ(error_code_name(refused.error.code), std::string("interior-corruption"));
  auto compaction = reopened->compact("{}", options.identity.created_at);
  CHECK(!compaction.ok());
}

GPF_TEST(store, compaction_preserves_state_and_rotates_the_log) {
  TempStoreDirectory directory("compaction");
  const StoreOpenOptions options = make_options(directory.path(), 9005);

  const std::string descriptor =
      "{\"store_id\":\"" + options.identity.id.to_string() + "\"}";
  auto store = DurableStore::open(options);
  REQUIRE(store.ok());
  REQUIRE(store->append(StoreRecordKind::SiteDescriptor, descriptor, options.identity.created_at).ok());
  REQUIRE(store->append(StoreRecordKind::GenerationFenced, encode_generation_record(Generation{3}, Generation{1}),
                        options.identity.created_at)
              .ok());
  const std::string snapshot_payload = "{\"phase\":\"snapshot\",\"generation\":3}";
  REQUIRE(store->compact(snapshot_payload, options.identity.created_at).ok());
  const std::string rotated_log = store->log_path().string();
  CHECK(rotated_log != "wal-1.log");
  REQUIRE(store->append(StoreRecordKind::SiteDescriptor, descriptor, options.identity.created_at).ok());
  const std::uint64_t tail_sequence = store->last_sequence().value;
  REQUIRE(store->close().ok());

  // After compaction the log holds only the records written after the snapshot.
  auto reopened = DurableStore::open(options);
  REQUIRE(reopened.ok());
  CHECK(reopened->recovery().outcome == RecoveryOutcome::Clean);
  CHECK_EQ(reopened->recovery().records_replayed, std::uint64_t{1});
  CHECK_EQ(reopened->last_sequence().value, tail_sequence);
  const std::string wal_name = wal_of(directory.path());
  CHECK(wal_name == rotated_log);

  auto files = platform::list_regular_files(directory.path());
  REQUIRE(files.ok());
  CHECK_EQ(std::count_if(files->begin(), files->end(),
                         [](const std::string& name) { return name.rfind("snapshot-", 0) == 0; }),
           std::ptrdiff_t{1});
  CHECK_EQ(std::count_if(files->begin(), files->end(),
                         [](const std::string& name) { return name.rfind("wal-", 0) == 0; }),
           std::ptrdiff_t{1});

  // The snapshot payload is recovered by the caller through the same helper it used to write it.
  auto files_after = platform::list_regular_files(directory.path());
  REQUIRE(files_after.ok());
  std::string snapshot_name;
  for (const std::string& name : *files_after) {
    if (name.rfind("snapshot-", 0) == 0) snapshot_name = name;
  }
  const JsonValue* unused = nullptr;
  (void)unused;
  auto snapshot_text = platform::read_file(directory.path() / snapshot_name, 1u << 20);
  REQUIRE(snapshot_text.ok());
  auto snapshot_json = JsonValue::parse(*snapshot_text);
  REQUIRE(snapshot_json.ok());
  auto payload = snapshot_json->require_string("payload");
  REQUIRE(payload.ok());
  CHECK_EQ(*payload, snapshot_payload);

  // A snapshot can never supersede state that was written after it.
  auto state = replay_records(reopened->identity(), reopened->records());
  REQUIRE(state.ok());
  CHECK_EQ(state->applied_sequence.value, tail_sequence);
}

GPF_TEST(store, compaction_cannot_delete_uncommitted_new_state) {
  TempStoreDirectory directory("compaction-race");
  const StoreOpenOptions options = make_options(directory.path(), 9006);

  const std::string descriptor =
      "{\"store_id\":\"" + options.identity.id.to_string() + "\"}";
  auto store = DurableStore::open(options);
  REQUIRE(store.ok());
  REQUIRE(store->append(StoreRecordKind::SiteDescriptor, descriptor, options.identity.created_at).ok());
  REQUIRE(store->compact("{\"covered\":1}", options.identity.created_at).ok());
  // State written after the snapshot must survive both the rotation and a reopen.
  REQUIRE(store->append(StoreRecordKind::SiteDescriptor, descriptor, options.identity.created_at).ok());
  REQUIRE(store->append(StoreRecordKind::SiteDescriptor, descriptor, options.identity.created_at).ok());
  REQUIRE(store->close().ok());

  auto reopened = DurableStore::open(options);
  REQUIRE(reopened.ok());
  CHECK_EQ(reopened->recovery().records_replayed, std::uint64_t{2});
  auto state = replay_records(reopened->identity(), reopened->records());
  if (!state.ok()) NOTE("replay failed: " + state.error.to_string());
  REQUIRE(state.ok());
  CHECK_EQ(state->applied_sequence.value, std::uint64_t{3});
}

GPF_TEST(store, manifest_and_snapshot_tampering_are_detected) {
  TempStoreDirectory directory("tampering");
  const StoreOpenOptions options = make_options(directory.path(), 9007);

  {
    auto store = DurableStore::open(options);
    REQUIRE(store.ok());
    REQUIRE(store->append(StoreRecordKind::SiteDescriptor, "{\"record\":1}", options.identity.created_at).ok());
    REQUIRE(store->compact("{\"covered\":1}", options.identity.created_at).ok());
    REQUIRE(store->close().ok());
  }

  const std::filesystem::path manifest_path = directory.path() / "MANIFEST";
  const std::string manifest = read_whole_file(manifest_path);

  // Hand-edited identity is detected because the manifest carries its own digest.
  const std::size_t epoch_position = manifest.find("\"epoch\":");
  REQUIRE(epoch_position != std::string::npos);
  std::string edited_manifest = manifest;
  edited_manifest.replace(epoch_position, 8, "\"epoch\":9");
  write_whole_file(manifest_path, edited_manifest);
  auto tampered_manifest = DurableStore::open(options);
  CHECK(!tampered_manifest.ok());
  CHECK_EQ(error_code_name(tampered_manifest.error.code), std::string("integrity-failure"));
  write_whole_file(manifest_path, manifest);

  // Unsupported format versions are refused rather than guessed at.
  write_whole_file(manifest_path, [&] {
    auto parsed = JsonValue::parse(manifest);
    parsed->set_field("format_version", JsonValue::integer(7));
    JsonValue::Object fields;
    for (const auto& field : parsed->object_items()) {
      if (field.first == "digest") continue;
      fields.push_back(field);
    }
    JsonValue without = JsonValue::object(std::move(fields));
    parsed->set_field("digest", JsonValue::text(Sha256::hash(without.dump(true)).to_hex()));
    return parsed->dump(true);
  }());
  auto unsupported = DurableStore::open(options);
  CHECK(!unsupported.ok());
  CHECK_EQ(error_code_name(unsupported.error.code), std::string("unsupported-format"));
  write_whole_file(manifest_path, manifest);

  // A manifest that points outside its directory is refused.
  write_whole_file(manifest_path, [&] {
    auto parsed = JsonValue::parse(manifest);
    parsed->set_field("wal", JsonValue::text("../escape.log"));
    JsonValue::Object fields;
    for (const auto& field : parsed->object_items()) {
      if (field.first == "digest") continue;
      fields.push_back(field);
    }
    JsonValue without = JsonValue::object(std::move(fields));
    parsed->set_field("digest", JsonValue::text(Sha256::hash(without.dump(true)).to_hex()));
    return parsed->dump(true);
  }());
  auto escaping = DurableStore::open(options);
  CHECK(!escaping.ok());
  CHECK_EQ(error_code_name(escaping.error.code), std::string("invalid-argument"));
  write_whole_file(manifest_path, manifest);

  // Damaged snapshot payloads are refused.
  auto files = platform::list_regular_files(directory.path());
  REQUIRE(files.ok());
  std::string snapshot_name;
  for (const std::string& name : *files) {
    if (name.rfind("snapshot-", 0) == 0) snapshot_name = name;
  }
  REQUIRE(!snapshot_name.empty());
  const std::filesystem::path snapshot_path = directory.path() / snapshot_name;
  const std::string snapshot = read_whole_file(snapshot_path);
  write_whole_file(snapshot_path, [&] {
    auto parsed = JsonValue::parse(snapshot);
    parsed->set_field("payload", JsonValue::text("{\"covered\":999}"));
    return parsed->dump(true);
  }());
  auto damaged = DurableStore::open(options);
  CHECK(!damaged.ok());
  CHECK_EQ(error_code_name(damaged.error.code), std::string("integrity-failure"));

  // Restoring the snapshot makes the store readable again: the failure was the damage, not the log.
  write_whole_file(snapshot_path, snapshot);
  auto restored = DurableStore::open(options);
  CHECK(restored.ok());
}

GPF_TEST(store, absurd_record_lengths_are_refused_without_allocating) {
  TempStoreDirectory directory("absurd-length");
  const StoreOpenOptions options = make_options(directory.path(), 9008);

  {
    auto store = DurableStore::open(options);
    REQUIRE(store.ok());
    REQUIRE(store->append(StoreRecordKind::SiteDescriptor, "{\"record\":1}", options.identity.created_at).ok());
    REQUIRE(store->close().ok());
  }

  const std::string wal_name = wal_of(directory.path());
  const std::filesystem::path wal_path = directory.path() / wal_name;
  std::string bytes = read_whole_file(wal_path);
  std::string hostile = bytes;
  hostile.append("GPF1", 4);
  hostile.push_back(static_cast<char>(static_cast<std::uint8_t>(StoreRecordKind::ReceiptAppended)));
  hostile.push_back(static_cast<char>(0));
  const std::uint32_t absurd = 0xFFFFFFFFu;
  for (int i = 0; i < 4; ++i) hostile.push_back(static_cast<char>((absurd >> (i * 8)) & 0xFFu));
  for (int i = 0; i < 4; ++i) hostile.push_back(static_cast<char>(0));
  for (int i = 0; i < 24; ++i) hostile.push_back(static_cast<char>(0));
  hostile.append("short");
  write_whole_file(wal_path, hostile);

  auto reopened = DurableStore::open(options);
  REQUIRE(reopened.ok());
  CHECK(reopened->recovery().outcome == RecoveryOutcome::TornTailDiscarded);
  CHECK_EQ(reopened->recovery().records_replayed, std::uint64_t{1});
  CHECK(reopened->is_writable());
}

GPF_TEST(store, missing_store_is_not_created_when_creation_is_disabled) {
  TempStoreDirectory directory("missing");
  StoreOpenOptions options = make_options(directory.path(), 9009);
  options.create_if_missing = false;
  auto store = DurableStore::open(options);
  CHECK(!store.ok());
  CHECK_EQ(error_code_name(store.error.code), std::string("not-found"));
}

GPF_TEST(store, new_store_requires_an_owner) {
  TempStoreDirectory directory("ownerless");
  StoreOpenOptions options;
  options.directory = directory.path();
  auto store = DurableStore::open(options);
  CHECK(!store.ok());
  CHECK_EQ(error_code_name(store.error.code), std::string("invalid-argument"));
}

GPF_TEST(store, replay_is_idempotent_and_refuses_gaps) {
  const StoreIdentity identity = make_options(std::filesystem::temp_directory_path(), 9010).identity;
  PersistedSiteState state;
  state.identity = identity;
  const std::string descriptor = "{\"store_id\":\"" + identity.id.to_string() + "\"}";

  StoreRecord first;
  first.kind = StoreRecordKind::SiteDescriptor;
  first.sequence = SequenceNumber{1};
  first.payload = descriptor;
  bool applied = false;
  CHECK(apply_record(state, first, applied).ok());
  CHECK(applied);

  // Delivering the same record again is not applying it twice.
  CHECK(apply_record(state, first, applied).ok());
  CHECK(!applied);

  // A gap is refused rather than reordered into place.
  StoreRecord third;
  third.kind = StoreRecordKind::SiteDescriptor;
  third.sequence = SequenceNumber{3};
  third.payload = descriptor;
  auto gap = apply_record(state, third, applied);
  CHECK(!gap.ok());
  CHECK_EQ(error_code_name(gap.error.code), std::string("reordered"));

  // A replay window may start anywhere above zero; sequence zero is never valid.
  PersistedSiteState fresh;
  fresh.identity = identity;
  CHECK(apply_record(fresh, third, applied).ok());
  CHECK(applied);
  StoreRecord zero;
  zero.kind = StoreRecordKind::SiteDescriptor;
  zero.sequence = SequenceNumber{0};
  zero.payload = "{\"store_id\":\"" + identity.id.to_string() + "\"}";
  PersistedSiteState another;
  another.identity = identity;
  auto zero_status = apply_record(another, zero, applied);
  CHECK(!zero_status.ok());
  CHECK_EQ(error_code_name(zero_status.error.code), std::string("reordered"));
}

GPF_TEST(store, typed_site_state_round_trips_through_json) {
  SiteFixture fixture;
  PersistedSiteState state;
  state.identity.id.value = fixture.ids.next();
  state.identity.federation = fixture.federation;
  state.identity.member = fixture.member;
  state.identity.site = fixture.site;
  state.applied_sequence = SequenceNumber{4};
  state.applied_global_generation = Generation{2};
  state.local_generation = Generation{3};
  state.next_receipt_sequence = SequenceNumber{9};
  state.authority_epoch = Epoch{5};
  state.capabilities = fixture.snapshot(Generation{1}, {{"power.metering", SemanticVersion{2, 0, 0}}});
  state.has_capabilities = true;
  state.catalog = fixture.catalog(Generation{3}, {{"power.metering", SemanticVersion{2, 0, 0}},
                                                  {"cooling.liquid", SemanticVersion{1, 0, 0}}});
  state.has_catalog = true;

  Rule rule = make_rule(fixture.ids, "power", "max_kw", int_value(100), RuleClass::Mandatory);
  state.accepted_bundles.push_back(fixture.global_bundle({rule}, Generation{2}));
  state.local_bundles.push_back(fixture.local_bundle(
      {make_rule(fixture.ids, "power", "min_kw", int_value(5), RuleClass::Default,
                 RuleScope::for_sites({fixture.site}))},
      Generation{3}));
  state.overrides.push_back(make_override(fixture.ids, fixture.federation, fixture.member, fixture.site,
                                          state.accepted_bundles[0].rules[0],
                                          state.accepted_bundles[0], Generation{3}, int_value(90),
                                          "site-reliability", "local envelope", GrantId{},
                                          fixture.now));
  Receipt receipt;
  receipt.federation = fixture.federation;
  receipt.member = fixture.member;
  receipt.site = fixture.site;
  receipt.bundle = state.accepted_bundles[0].id;
  receipt.global_generation = Generation{2};
  receipt.kind = ReceiptKind::Accepted;
  receipt.reason_code = "accepted";
  receipt.detail = "bundle accepted for activation";
  receipt.at = fixture.now;
  receipt.sequence = SequenceNumber{8};
  REQUIRE(seal_receipt(receipt).ok());
  state.receipts.push_back(receipt);

  const std::string dumped = site_state_to_json(state).dump(true);
  auto parsed = JsonValue::parse(dumped);
  REQUIRE(parsed.ok());
  auto restored = site_state_from_json(*parsed);
  if (!restored.ok()) NOTE("site_state_from_json: " + restored.error.to_string());
  REQUIRE(restored.ok());
  CHECK_EQ(restored->accepted_bundles.size(), std::size_t{1});
  CHECK_EQ(restored->local_bundles.size(), std::size_t{1});
  CHECK_EQ(restored->overrides.size(), std::size_t{1});
  CHECK_EQ(restored->receipts.size(), std::size_t{1});
  CHECK(restored->receipts[0].digest == receipt.digest);
  CHECK_EQ(restored->applied_sequence.value, std::uint64_t{4});
  CHECK_EQ(restored->next_receipt_sequence.value, std::uint64_t{9});
  CHECK(restored->has_capabilities);
  CHECK(restored->has_catalog);
  CHECK_EQ(restored->catalog.capabilities.size(), std::size_t{2});
  CHECK_EQ(restored->catalog.generation.value, std::uint64_t{3});
  CHECK_EQ(restored->accepted_bundles[0].integrity_digest.to_hex(),
           state.accepted_bundles[0].integrity_digest.to_hex());
}

GPF_TEST(store, independent_process_crash_is_recovered) {
  const std::vector<std::string>& args = positional_args();
  if (args.empty()) {
    NOTE("helper binary path was not provided by the build system");
    CHECK(false);
    return;
  }
  const std::string helper = args[0];
  TempStoreDirectory directory("crash");
  const StoreOpenOptions options = make_options(directory.path(), 9011);

  auto exit_code = platform::run_process(
      helper, {"write-then-torn", directory.path().string(), "9011"});
  REQUIRE(exit_code.ok());
  NOTE("helper exit code " + std::to_string(*exit_code));

  auto recovered = DurableStore::open(options);
  if (!recovered.ok()) NOTE("reopen failed: " + recovered.error.to_string());
  REQUIRE(recovered.ok());
  CHECK(recovered->recovery().outcome == RecoveryOutcome::TornTailDiscarded);
  CHECK_EQ(recovered->recovery().records_replayed, std::uint64_t{3});
  CHECK(recovered->is_writable());
  CHECK_EQ(recovered->identity().id.to_string(), options.identity.id.to_string());

  // The recovered store is usable and its state survives another full restart.
  REQUIRE(recovered->append(StoreRecordKind::SiteDescriptor, "{\"after\":\"crash\"}",
                            options.identity.created_at)
              .ok());
  REQUIRE(recovered->close().ok());

  auto verify_code =
      platform::run_process(helper, {"reopen-verify", directory.path().string(), "9011"});
  REQUIRE(verify_code.ok());
  if (*verify_code != 0) NOTE("helper reopen-verify reported exit " + std::to_string(*verify_code));
  CHECK_EQ(*verify_code, 0);

  auto final_state = DurableStore::open(options);
  REQUIRE(final_state.ok());
  CHECK(final_state->recovery().outcome == RecoveryOutcome::Clean);
  CHECK_EQ(final_state->recovery().records_replayed, std::uint64_t{4});
}

GPF_TEST(store, records_survive_a_clean_close_from_another_process) {
  const std::vector<std::string>& args = positional_args();
  if (args.empty()) {
    NOTE("helper binary path was not provided by the build system");
    CHECK(false);
    return;
  }
  TempStoreDirectory directory("clean-process");
  const StoreOpenOptions options = make_options(directory.path(), 9012);
  auto exit_code = platform::run_process(args[0], {"write-then-clean", directory.path().string(), "9012"});
  REQUIRE(exit_code.ok());
  CHECK_EQ(*exit_code, 0);

  auto store = DurableStore::open(options);
  REQUIRE(store.ok());
  CHECK(store->recovery().outcome == RecoveryOutcome::Clean);
  CHECK_EQ(store->recovery().records_replayed, std::uint64_t{3});
  CHECK_EQ(store->identity().id.to_string(), options.identity.id.to_string());
}
