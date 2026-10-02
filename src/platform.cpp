#include "gpf/platform.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace gpf::platform {
namespace {

Status io_failure(const std::string& message, const std::filesystem::path& path,
                  const std::error_code& code = {}) {
  const std::string detail = path.string() + (code ? " (" + code.message() + ")" : std::string());
  if (code && code.value() == static_cast<int>(std::errc::no_space_on_device)) {
    return Status::failure(ErrorCode::DiskFull, message, detail);
  }
  if (code && (code.value() == static_cast<int>(std::errc::permission_denied) ||
               code.value() == static_cast<int>(std::errc::operation_not_permitted))) {
    return Status::failure(ErrorCode::PermissionDenied, message, detail);
  }
  return Status::failure(ErrorCode::IoError, message, detail);
}

std::filesystem::path temporary_sibling(const std::filesystem::path& destination) {
  return std::filesystem::path(destination.string() + ".tmp");
}

// The C runtime marks std::fopen as deprecated on Windows. Rather than disabling that warning
// globally, the checked variant is used there and its status is honored.
#if defined(_WIN32)
std::FILE* open_file(const std::filesystem::path& path, const char* mode) {
  std::FILE* file = nullptr;
  if (fopen_s(&file, path.string().c_str(), mode) != 0) return nullptr;
  return file;
}
#else
std::FILE* open_file(const std::filesystem::path& path, const char* mode) {
  return std::fopen(path.string().c_str(), mode);
}
#endif

}  // namespace

Result<std::string> read_file(const std::filesystem::path& path, std::uint64_t max_bytes) {
  std::error_code size_error;
  const std::uintmax_t size = std::filesystem::file_size(path, size_error);
  if (size_error) {
    if (size_error.value() == static_cast<int>(std::errc::no_such_file_or_directory)) {
      return Result<std::string>::failure(ErrorCode::NotFound, "file does not exist", path.string());
    }
    return Result<std::string>::failure(ErrorCode::IoError, "cannot stat file", path.string());
  }
  if (size > max_bytes) {
    return Result<std::string>::failure(ErrorCode::TooLarge, "file exceeds the read limit",
                                        path.string() + " (" + std::to_string(size) + " bytes)");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return Result<std::string>::failure(ErrorCode::IoError, "cannot open file for reading", path.string());
  }
  std::string content;
  content.resize(static_cast<std::size_t>(size));
  if (size > 0) stream.read(content.data(), static_cast<std::streamsize>(size));
  if (!stream && !stream.eof()) {
    return Result<std::string>::failure(ErrorCode::IoError, "cannot read file completely", path.string());
  }
  content.resize(static_cast<std::size_t>(stream.gcount()));
  return Result<std::string>::success(std::move(content));
}

Status write_file_atomic(const std::filesystem::path& destination, std::string_view content) {
  const std::filesystem::path temporary = temporary_sibling(destination);
  {
    std::FILE* file = open_file(temporary, "wb");
    if (file == nullptr) {
      return io_failure("cannot open temporary file for writing", temporary);
    }
    if (!content.empty()) {
      const std::size_t written = std::fwrite(content.data(), 1, content.size(), file);
      if (written != content.size()) {
        std::fclose(file);
        std::remove(temporary.string().c_str());
        return io_failure("short write while writing temporary file", temporary);
      }
    }
    if (std::fflush(file) != 0) {
      std::fclose(file);
      std::remove(temporary.string().c_str());
      return io_failure("cannot flush temporary file", temporary);
    }
#if defined(_WIN32)
    if (_commit(_fileno(file)) != 0) {
      std::fclose(file);
      std::remove(temporary.string().c_str());
      return io_failure("cannot flush temporary file to disk", temporary);
    }
#else
    if (::fsync(fileno(file)) != 0) {
      std::fclose(file);
      std::remove(temporary.string().c_str());
      return io_failure("cannot flush temporary file to disk", temporary);
    }
#endif
    if (std::fclose(file) != 0) {
      std::remove(temporary.string().c_str());
      return io_failure("cannot close temporary file", temporary);
    }
  }
#if defined(_WIN32)
  // std::filesystem::rename does not replace an existing destination on Windows.
  if (MoveFileExW(temporary.wstring().c_str(), destination.wstring().c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    const DWORD error = GetLastError();
    std::remove(temporary.string().c_str());
    return Status::failure(ErrorCode::IoError, "cannot replace destination file",
                           destination.string() + " (windows error " + std::to_string(error) + ")");
  }
#else
  std::error_code rename_error;
  std::filesystem::rename(temporary, destination, rename_error);
  if (rename_error) {
    std::remove(temporary.string().c_str());
    return io_failure("cannot replace destination file", destination, rename_error);
  }
#endif
  return sync_directory(destination.parent_path());
}

Status append_file_durable(const std::filesystem::path& path, std::string_view bytes) {
  std::FILE* file = open_file(path, "ab");
  if (file == nullptr) {
    return io_failure("cannot open file for appending", path);
  }
  if (!bytes.empty()) {
    const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), file);
    if (written != bytes.size()) {
      std::fclose(file);
      return io_failure("short write while appending", path);
    }
  }
  if (std::fflush(file) != 0) {
    std::fclose(file);
    return io_failure("cannot flush appended data", path);
  }
#if defined(_WIN32)
  if (_commit(_fileno(file)) != 0) {
    std::fclose(file);
    return io_failure("cannot flush appended data to disk", path);
  }
#else
  if (::fsync(fileno(file)) != 0) {
    std::fclose(file);
    return io_failure("cannot flush appended data to disk", path);
  }
#endif
  if (std::fclose(file) != 0) {
    return io_failure("cannot close appended file", path);
  }
  return Status::success();
}

Status sync_directory(const std::filesystem::path& directory) {
#if defined(_WIN32)
  // Windows offers no portable directory flush. The file itself was flushed and the rename is
  // atomic; the directory entry durability is left to the platform, and that limitation is
  // documented rather than papered over.
  (void)directory;
  return Status::success();
#else
  const int descriptor = ::open(directory.string().c_str(), O_RDONLY);
  if (descriptor < 0) {
    return Status::failure(ErrorCode::IoError, "cannot open directory for synchronization",
                           directory.string());
  }
  const int result = ::fsync(descriptor);
  ::close(descriptor);
  if (result != 0) {
    return Status::failure(ErrorCode::IoError, "cannot synchronize directory", directory.string());
  }
  return Status::success();
#endif
}

Status truncate_file(const std::filesystem::path& path, std::uint64_t size) {
  std::error_code error;
  std::filesystem::resize_file(path, size, error);
  if (error) return io_failure("cannot truncate file", path, error);
  return Status::success();
}

Result<std::uint64_t> file_size(const std::filesystem::path& path) {
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error) {
    return Result<std::uint64_t>::failure(ErrorCode::NotFound, "cannot determine file size",
                                          path.string());
  }
  return Result<std::uint64_t>::success(static_cast<std::uint64_t>(size));
}

bool path_exists(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error);
}

Status remove_file_if_present(const std::filesystem::path& path) {
  std::error_code error;
  if (!std::filesystem::exists(path, error)) return Status::success();
  if (!std::filesystem::remove(path, error)) {
    return io_failure("cannot remove file", path, error);
  }
  return Status::success();
}

Status ensure_directory(const std::filesystem::path& directory) {
  std::error_code error;
  if (std::filesystem::exists(directory, error)) {
    if (!std::filesystem::is_directory(directory, error)) {
      return Status::failure(ErrorCode::InvalidArgument, "path exists and is not a directory",
                             directory.string());
    }
    return Status::success();
  }
  std::filesystem::create_directories(directory, error);
  if (error) return io_failure("cannot create directory", directory, error);
  return Status::success();
}

Result<std::vector<std::string>> list_regular_files(const std::filesystem::path& directory) {
  std::error_code error;
  std::vector<std::string> names;
  std::filesystem::directory_iterator iterator(directory, error);
  if (error) {
    return Result<std::vector<std::string>>::failure(ErrorCode::IoError,
                                                     "cannot list directory", directory.string());
  }
  for (const auto& entry : iterator) {
    std::error_code status_error;
    // is_regular_file follows nothing: a symlink or junction reports as such and is skipped.
    if (!entry.is_regular_file(status_error)) continue;
    names.push_back(entry.path().filename().string());
  }
  std::sort(names.begin(), names.end());
  return Result<std::vector<std::string>>::success(std::move(names));
}

bool is_regular_file(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::is_regular_file(path, error);
}

bool is_within_directory(const std::filesystem::path& directory,
                         const std::filesystem::path& candidate) {
  std::error_code error;
  const std::filesystem::path base = std::filesystem::weakly_canonical(directory, error);
  if (error) return false;
  const std::filesystem::path target = std::filesystem::weakly_canonical(candidate, error);
  if (error) return false;
  const std::filesystem::path relative = target.lexically_relative(base);
  if (relative.empty()) return target == base;
  const std::string text = relative.string();
  if (text.rfind("..", 0) == 0) return false;
  return !relative.is_absolute();
}

Result<int> run_process(const std::string& program, const std::vector<std::string>& arguments) {
  const auto quotable = [](const std::string& value) {
    if (value.empty() || value.size() > 32767) return false;
    if (value.find('"') != std::string::npos) return false;
    if (value.find('\n') != std::string::npos || value.find('\r') != std::string::npos) return false;
#if !defined(_WIN32)
    if (value.find('\'') != std::string::npos) return false;
#endif
    return true;
  };
  if (!quotable(program)) {
    return Result<int>::failure(ErrorCode::InvalidArgument, "program path cannot be quoted safely",
                                escape_preview(program));
  }
  for (const std::string& argument : arguments) {
    if (!quotable(argument)) {
      return Result<int>::failure(ErrorCode::InvalidArgument, "argument cannot be quoted safely",
                                  escape_preview(argument));
    }
  }
#if defined(_WIN32)
  // cmd.exe strips the outer quotes of a command that begins with one, so the whole line gets an
  // extra pair of quotes: cmd /c ""program" "argument"".
  std::string line = "\"" + program + "\"";
  for (const std::string& argument : arguments) line += " \"" + argument + "\"";
  line = "\"" + line + "\"";
#else
  std::string line = "'" + program + "'";
  for (const std::string& argument : arguments) line += " '" + argument + "'";
#endif
  const int code = std::system(line.c_str());
  if (code == -1) {
    return Result<int>::failure(ErrorCode::Unavailable, "cannot start process", program);
  }
  return Result<int>::success(code);
}

namespace {

#if defined(_WIN32)
std::string windows_quote(const std::string& value) {
  // CommandLineToArgvW rules: wrap in quotes and escape embedded quotes with backslashes.
  std::string out = "\"";
  std::size_t backslashes = 0;
  for (char c : value) {
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      out.append(backslashes * 2 + 1, '\\');
      out.push_back('"');
      backslashes = 0;
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0;
    out.push_back(c);
  }
  out.append(backslashes * 2, '\\');
  out.push_back('"');
  return out;
}
#endif

}  // namespace

Result<ProcessHandle> spawn_process(const std::string& program,
                                    const std::vector<std::string>& arguments,
                                    const std::filesystem::path& stdout_path,
                                    const std::filesystem::path& stderr_path) {
  if (!std::filesystem::exists(program)) {
    return Result<ProcessHandle>::failure(ErrorCode::NotFound, "program does not exist", program);
  }
#if defined(_WIN32)
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  HANDLE out = CreateFileW(stdout_path.wstring().c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (out == INVALID_HANDLE_VALUE) {
    return Result<ProcessHandle>::failure(ErrorCode::IoError, "cannot create the output file",
                                          stdout_path.string());
  }
  HANDLE err = CreateFileW(stderr_path.wstring().c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (err == INVALID_HANDLE_VALUE) {
    CloseHandle(out);
    return Result<ProcessHandle>::failure(ErrorCode::IoError, "cannot create the error file",
                                          stderr_path.string());
  }
  std::string command = windows_quote(program);
  for (const std::string& argument : arguments) command += " " + windows_quote(argument);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = out;
  startup.hStdError = err;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION information{};
  std::wstring wide(command.begin(), command.end());
  const BOOL created = CreateProcessW(nullptr, wide.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr,
                                      &startup, &information);
  CloseHandle(out);
  CloseHandle(err);
  if (!created) {
    return Result<ProcessHandle>::failure(ErrorCode::Unavailable, "cannot start the process",
                                          program + " (windows error " + std::to_string(GetLastError()) + ")");
  }
  CloseHandle(information.hThread);
  ProcessHandle handle;
  handle.handle = reinterpret_cast<std::intptr_t>(information.hProcess);
  return Result<ProcessHandle>::success(handle);
#else
  const pid_t pid = ::fork();
  if (pid < 0) {
    return Result<ProcessHandle>::failure(ErrorCode::Unavailable, "cannot fork", program);
  }
  if (pid == 0) {
    const int out = ::open(stdout_path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    const int err = ::open(stderr_path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) ::dup2(out, STDOUT_FILENO);
    if (err >= 0) ::dup2(err, STDERR_FILENO);
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(program.c_str()));
    for (const std::string& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    ::execv(program.c_str(), argv.data());
    std::_Exit(127);
  }
  ProcessHandle handle;
  handle.handle = static_cast<std::intptr_t>(pid);
  return Result<ProcessHandle>::success(handle);
#endif
}

Result<int> wait_process(ProcessHandle& process) {
  if (!process.valid()) {
    return Result<int>::failure(ErrorCode::InvalidArgument, "process handle is not valid");
  }
#if defined(_WIN32)
  const DWORD result = WaitForSingleObject(reinterpret_cast<HANDLE>(process.handle), INFINITE);
  if (result != WAIT_OBJECT_0) {
    return Result<int>::failure(ErrorCode::IoError, "waiting for the process failed");
  }
  DWORD code = 0;
  if (!GetExitCodeProcess(reinterpret_cast<HANDLE>(process.handle), &code)) {
    return Result<int>::failure(ErrorCode::IoError, "cannot read the process exit code");
  }
  CloseHandle(reinterpret_cast<HANDLE>(process.handle));
  process.handle = -1;
  process.waited = true;
  process.exit_code = static_cast<int>(code);
  return Result<int>::success(process.exit_code);
#else
  int status = 0;
  if (::waitpid(static_cast<pid_t>(process.handle), &status, 0) < 0) {
    return Result<int>::failure(ErrorCode::IoError, "waiting for the process failed");
  }
  process.handle = -1;
  process.waited = true;
  process.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  return Result<int>::success(process.exit_code);
#endif
}

Status terminate_process(ProcessHandle& process) {
  if (!process.valid()) return Status::success();
#if defined(_WIN32)
  const BOOL terminated = TerminateProcess(reinterpret_cast<HANDLE>(process.handle), 1);
  CloseHandle(reinterpret_cast<HANDLE>(process.handle));
  process.handle = -1;
  if (!terminated) {
    return Status::failure(ErrorCode::IoError, "cannot terminate the process");
  }
  return Status::success();
#else
  const int result = ::kill(static_cast<pid_t>(process.handle), SIGTERM);
  process.handle = -1;
  if (result != 0) return Status::failure(ErrorCode::IoError, "cannot terminate the process");
  return Status::success();
#endif
}

Millis system_now_millis() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void exit_immediately(int code) { std::_Exit(code); }

}  // namespace gpf::platform
