#pragma once
// Global Policy Federation — portable file and process primitives.
//
// Deliberately small and dependency-free: the deterministic core never touches this header, and
// no policy decision depends on a platform behavior. Durability here means what the platform
// actually offers, and the limitations are stated rather than assumed.

#include "gpf/base.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace gpf::platform {

// Largest file this boundary will read in one piece. Anything larger is refused before reading.
inline constexpr std::uint64_t kMaxReadBytes = 512ull * 1024ull * 1024ull;

Result<std::string> read_file(const std::filesystem::path& path,
                              std::uint64_t max_bytes = kMaxReadBytes);

// Durable write: write to a sibling temporary file, flush it to stable storage, then replace the
// destination atomically. A reader either sees the previous content or the new content.
Status write_file_atomic(const std::filesystem::path& destination, std::string_view content);

// Append bytes and flush to stable storage before returning. The flush boundary is the platform
// flush (FlushFileBuffers / fsync), which is the strongest guarantee available without fsync of
// every directory entry.
Status append_file_durable(const std::filesystem::path& path, std::string_view bytes);

// Best-effort directory synchronization after a rename. On Windows this is a documented no-op
// because the platform offers no portable directory flush; on POSIX the directory is fsynced.
Status sync_directory(const std::filesystem::path& directory);

Status truncate_file(const std::filesystem::path& path, std::uint64_t size);

Result<std::uint64_t> file_size(const std::filesystem::path& path);

bool path_exists(const std::filesystem::path& path);

// Removes a file if present. Missing files are not an error.
Status remove_file_if_present(const std::filesystem::path& path);

// Creates a directory and any missing parents.
Status ensure_directory(const std::filesystem::path& directory);

// Lists the regular files of a directory with their names only, sorted. Never follows a directory
// entry that is not a regular file, so junctions and symlinks cannot redirect the caller.
Result<std::vector<std::string>> list_regular_files(const std::filesystem::path& directory);

bool is_regular_file(const std::filesystem::path& path);

// True when the path resolves into the given directory (defence against traversal).
bool is_within_directory(const std::filesystem::path& directory, const std::filesystem::path& candidate);

// Runs a program with arguments in a separate OS process and returns its exit code. Arguments
// are quoted by this function rather than by the caller, and an argument that cannot be quoted
// safely (an embedded quote or newline) is refused instead of guessed at. Used by tests to drive
// real, independent OS processes; production code paths never call it.
Result<int> run_process(const std::string& program, const std::vector<std::string>& arguments);

// A handle to an independently running OS process whose standard output and error are redirected
// to files. Used to drive real multiprocess behavior; production code paths never call it.
struct ProcessHandle {
  std::intptr_t handle{-1};
  bool waited{false};
  int exit_code{-1};

  bool valid() const noexcept { return handle != -1; }
};

Result<ProcessHandle> spawn_process(const std::string& program,
                                    const std::vector<std::string>& arguments,
                                    const std::filesystem::path& stdout_path,
                                    const std::filesystem::path& stderr_path);

// Blocks until the process exits and returns its exit code.
Result<int> wait_process(ProcessHandle& process);

// Non-blocking process state query, for callers that must not block: a readiness wait ends when the
// child either becomes ready or exits. An exited process is reaped here and its exit code is
// remembered, so a later wait_process returns the same value.
Result<bool> process_has_exited(ProcessHandle& process);

// Requests termination of a running process.
Status terminate_process(ProcessHandle& process);

// Current wall-clock time in milliseconds since the Unix epoch.
Millis system_now_millis();

// Terminates the current process immediately without unwinding or flushing. Test helpers use this
// to model a crash at a chosen point.
[[noreturn]] void exit_immediately(int code);

}  // namespace gpf::platform
