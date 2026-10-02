// Independent OS process used by the durability tests to model a crash at a chosen point.
//
// Modes:
//   write-then-clean <directory>  write three records, close cleanly, exit 0
//   write-then-torn  <directory>  write three records, append a partial record, exit without
//                                 unwinding or flushing (models a crash mid-append)
//   reopen-verify    <directory>  reopen the store, print the recovery outcome and record count

#include "gpf/platform.hpp"
#include "gpf/store.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace gpf;

namespace {

int usage() {
  std::fprintf(stderr,
               "usage: gpf_store_crash_helper <write-then-clean|write-then-torn|reopen-verify> <dir> <seed>\n");
  return 2;
}

Status append_sample_records(DurableStore& store, Timestamp now, const std::string& tag) {
  Status status = store.append(StoreRecordKind::SiteDescriptor,
                               "{\"kind\":\"descriptor\",\"tag\":\"" + tag + "\"}", now);
  if (!status.ok()) return status;
  status = store.append(StoreRecordKind::GenerationFenced, encode_epoch_record(Epoch{1}), now);
  if (!status.ok()) return status;
  return store.append(StoreRecordKind::GenerationFenced,
                      encode_generation_record(Generation{1}, Generation{2}), now);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 4) return usage();
  const std::string mode = argv[1];
  const std::string directory = argv[2];
  const std::uint64_t seed = std::strtoull(argv[3], nullptr, 10);
  const Timestamp now = Timestamp{platform::system_now_millis()};

  // The identity is derived from the same seed the driving test uses, so both processes address
  // one store rather than creating two.
  IdGenerator ids(seed);
  StoreOpenOptions options;
  options.directory = directory;
  options.identity.id.value = ids.next();
  options.identity.federation.value = ids.next();
  options.identity.member.value = ids.next();
  options.identity.site.value = ids.next();
  options.identity.created_at = now;

  if (mode == "write-then-clean") {
    auto store = DurableStore::open(options);
    if (!store.ok()) {
      std::fprintf(stderr, "open failed: %s\n", store.error.to_string().c_str());
      return 1;
    }
    const Status status = append_sample_records(*store, now, "clean");
    if (!status.ok()) {
      std::fprintf(stderr, "append failed: %s\n", status.error.to_string().c_str());
      return 1;
    }
    const Status closed = store->close();
    return closed.ok() ? 0 : 1;
  }

  if (mode == "write-then-torn") {
    auto store = DurableStore::open(options);
    if (!store.ok()) {
      std::fprintf(stderr, "open failed: %s\n", store.error.to_string().c_str());
      return 1;
    }
    const Status status = append_sample_records(*store, now, "torn");
    if (!status.ok()) {
      std::fprintf(stderr, "append failed: %s\n", status.error.to_string().c_str());
      return 1;
    }
    // A partial record: header announcing 64 payload bytes, followed by only 10 of them.
    std::string partial;
    partial.append("GPF1", 4);
    partial.push_back(static_cast<char>(static_cast<std::uint8_t>(StoreRecordKind::ReceiptAppended)));
    partial.push_back(static_cast<char>(0));
    const std::uint32_t announced = 64;
    for (int i = 0; i < 4; ++i) partial.push_back(static_cast<char>((announced >> (i * 8)) & 0xFFu));
    for (int i = 0; i < 4; ++i) partial.push_back(static_cast<char>(0xAB));
    for (int i = 0; i < 8; ++i) partial.push_back(static_cast<char>(0));
    for (int i = 0; i < 8; ++i) partial.push_back(static_cast<char>(0));
    for (int i = 0; i < 8; ++i) partial.push_back(static_cast<char>(0));
    partial.append("0123456789");
    const Status torn = platform::append_file_durable(store->directory() / store->log_path(), partial);
    if (!torn.ok()) {
      std::fprintf(stderr, "partial append failed: %s\n", torn.error.to_string().c_str());
      return 1;
    }
    // Crash: no destructors, no flush, no close.
    platform::exit_immediately(3);
  }

  if (mode == "reopen-verify") {
    auto store = DurableStore::open(options);
    if (!store.ok()) {
      std::printf("open-failed %s\n", store.error.to_string().c_str());
      return 1;
    }
    std::printf("outcome=%s records=%llu writable=%d epoch=%llu\n",
                recovery_outcome_name(store->recovery().outcome),
                static_cast<unsigned long long>(store->recovery().records_replayed),
                store->is_writable() ? 1 : 0,
                static_cast<unsigned long long>(store->epoch().value));
    return 0;
  }

  return usage();
}
