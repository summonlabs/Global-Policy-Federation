#include "gpf/net.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace gpf::net {
namespace {

#if defined(_WIN32)
using NativeHandle = SOCKET;
constexpr NativeHandle kInvalid = INVALID_SOCKET;
#else
using NativeHandle = int;
constexpr NativeHandle kInvalid = -1;
#endif

std::once_flag g_init_once;

void initialize() {
  std::call_once(g_init_once, [] {
#if defined(_WIN32)
    WSADATA data;
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    (void)result;
#endif
  });
}

Status socket_error(const std::string& message, const std::string& detail = {}) {
#if defined(_WIN32)
  const int code = WSAGetLastError();
  if (code == WSAETIMEDOUT) return Status::failure(ErrorCode::Unavailable, message, detail);
  return Status::failure(ErrorCode::IoError, message, detail + " (winsock " + std::to_string(code) + ")");
#else
  return Status::failure(ErrorCode::IoError, message, detail + " (errno " + std::to_string(errno) + ")");
#endif
}

void close_handle(NativeHandle handle) {
  if (handle == kInvalid) return;
#if defined(_WIN32)
  closesocket(handle);
#else
  ::close(handle);
#endif
}

Status set_nodelay(NativeHandle handle) {
  const int enabled = 1;
  const char* bytes = reinterpret_cast<const char*>(&enabled);
  if (::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, bytes, sizeof(enabled)) != 0) {
    return socket_error("cannot configure the socket");
  }
  return Status::success();
}

}  // namespace

void ensure_initialized() { initialize(); }

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = -1; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this == &other) return *this;
  close();
  handle_ = other.handle_;
  other.handle_ = -1;
  return *this;
}

bool Socket::is_open() const noexcept { return handle_ != -1; }

void Socket::close() {
  if (handle_ == -1) return;
  close_handle(static_cast<NativeHandle>(handle_));
  handle_ = -1;
}

Status Socket::shutdown_both() {
  if (handle_ == -1) return Status::success();
#if defined(_WIN32)
  if (::shutdown(static_cast<NativeHandle>(handle_), SD_BOTH) != 0) {
    return socket_error("cannot shut down the connection");
  }
#else
  if (::shutdown(static_cast<NativeHandle>(handle_), SHUT_RDWR) != 0) {
    return socket_error("cannot shut down the connection");
  }
#endif
  return Status::success();
}

bool is_valid_host(const std::string& host) noexcept {
  if (host.empty() || host.size() > 128) return false;
  for (char c : host) {
    const auto value = static_cast<unsigned char>(c);
    const bool allowed = (value >= '0' && value <= '9') || (value >= 'a' && value <= 'z') ||
                         (value >= 'A' && value <= 'Z') || c == '.' || c == ':' || c == '-' ||
                         c == '_';
    if (!allowed) return false;
  }
  // No shell metacharacters, no path separators, no spaces: a host is a host.
  return true;
}

Result<Socket> Socket::listen(const std::string& address, std::uint16_t port, int backlog) {
  initialize();
  if (!is_valid_host(address)) {
    return Result<Socket>::failure(ErrorCode::InvalidArgument, "invalid listen address", address);
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const int resolved = ::getaddrinfo(address.empty() ? nullptr : address.c_str(), service.c_str(),
                                     &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Result<Socket>::failure(ErrorCode::Unavailable, "cannot resolve the listen address",
                                   address);
  }
  Socket socket;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeHandle handle = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalid) continue;
    const int reuse = 1;
    ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (::bind(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0 &&
        ::listen(handle, backlog) == 0) {
      socket.handle_ = static_cast<std::intptr_t>(handle);
      break;
    }
    close_handle(handle);
  }
  ::freeaddrinfo(results);
  if (!socket.is_open()) {
    return Result<Socket>::failure(ErrorCode::Unavailable, "cannot bind and listen", address);
  }
  return Result<Socket>::success(std::move(socket));
}

Result<Socket> Socket::connect(const std::string& address, std::uint16_t port) {
  initialize();
  if (!is_valid_host(address)) {
    return Result<Socket>::failure(ErrorCode::InvalidArgument, "invalid host address", address);
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const int resolved = ::getaddrinfo(address.c_str(), service.c_str(), &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Result<Socket>::failure(ErrorCode::Unavailable, "cannot resolve the host address",
                                   address);
  }
  Socket socket;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeHandle handle = ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalid) continue;
    if (::connect(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
      socket.handle_ = static_cast<std::intptr_t>(handle);
      (void)set_nodelay(handle);
      break;
    }
    close_handle(handle);
  }
  ::freeaddrinfo(results);
  if (!socket.is_open()) {
    return Result<Socket>::failure(ErrorCode::NotConnected, "cannot connect to the peer",
                                   address + ":" + service);
  }
  return Result<Socket>::success(std::move(socket));
}

Result<Socket> Socket::accept() {
  if (!is_open()) {
    return Result<Socket>::failure(ErrorCode::InvalidState, "listener is not open");
  }
  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  const NativeHandle handle =
      ::accept(static_cast<NativeHandle>(handle_), reinterpret_cast<sockaddr*>(&storage), &length);
  if (handle == kInvalid) {
    return Result<Socket>::failure(ErrorCode::NotConnected, "accept failed on the listener");
  }
  Socket socket;
  socket.handle_ = static_cast<std::intptr_t>(handle);
  (void)set_nodelay(handle);
  return Result<Socket>::success(std::move(socket));
}

Status Socket::prepare_accepted() { return Status::success(); }

Status Socket::send_all(std::string_view bytes) {
  if (!is_open()) return Status::failure(ErrorCode::NotConnected, "socket is not open");
  std::size_t sent = 0;
  while (sent < bytes.size()) {
    const std::size_t remaining = bytes.size() - sent;
    const int chunk = static_cast<int>(std::min<std::size_t>(remaining, 1u << 20));
#if defined(_WIN32)
    const int result = ::send(static_cast<NativeHandle>(handle_), bytes.data() + sent, chunk, 0);
#else
    const ssize_t result = ::send(static_cast<NativeHandle>(handle_), bytes.data() + sent,
                                  static_cast<std::size_t>(chunk), 0);
#endif
    if (result <= 0) return socket_error("send failed", std::to_string(sent) + " bytes written");
    sent += static_cast<std::size_t>(result);
  }
  return Status::success();
}

Result<std::string> Socket::receive_frame(std::size_t max_bytes) {
  if (!is_open()) return Result<std::string>::failure(ErrorCode::NotConnected, "socket is not open");
  std::string header;
  header.resize(4);
  std::size_t received = 0;
  while (received < 4) {
#if defined(_WIN32)
    const int result = ::recv(static_cast<NativeHandle>(handle_), header.data() + received,
                              static_cast<int>(4 - received), 0);
#else
    const ssize_t result = ::recv(static_cast<NativeHandle>(handle_), header.data() + received,
                                  4 - received, 0);
#endif
    if (result == 0) return Result<std::string>::failure(ErrorCode::NotConnected, "peer closed the connection");
    if (result < 0) return Result<std::string>::failure(ErrorCode::IoError, "receive failed");
    received += static_cast<std::size_t>(result);
  }
  std::uint32_t length = 0;
  for (int i = 0; i < 4; ++i) {
    length |= static_cast<std::uint32_t>(static_cast<unsigned char>(header[static_cast<std::size_t>(i)]))
              << (i * 8);
  }
  if (length == 0) {
    close();
    return Result<std::string>::failure(ErrorCode::MalformedInput, "empty frame");
  }
  if (length > max_bytes || length > limits::kMaxWireMessageBytes) {
    // The declared length is already consumed, so the stream can no longer be interpreted safely.
    // The connection is closed instead of leaving a desynchronized stream for the next read.
    close();
    return Result<std::string>::failure(ErrorCode::TooLarge, "frame exceeds the size limit",
                                        std::to_string(length));
  }
  std::string payload;
  payload.resize(length);
  std::size_t filled = 0;
  while (filled < length) {
#if defined(_WIN32)
    const int result = ::recv(static_cast<NativeHandle>(handle_), payload.data() + filled,
                              static_cast<int>(length - filled), 0);
#else
    const ssize_t result = ::recv(static_cast<NativeHandle>(handle_), payload.data() + filled,
                                  length - filled, 0);
#endif
    if (result == 0) {
      return Result<std::string>::failure(ErrorCode::NotConnected, "peer closed mid-frame",
                                          std::to_string(filled) + " of " + std::to_string(length));
    }
    if (result < 0) return Result<std::string>::failure(ErrorCode::IoError, "receive failed");
    filled += static_cast<std::size_t>(result);
  }
  return Result<std::string>::success(std::move(payload));
}

Status Socket::send_frame(std::string_view payload) {
  if (payload.size() > limits::kMaxWireMessageBytes) {
    return Status::failure(ErrorCode::TooLarge, "frame exceeds the size limit",
                           std::to_string(payload.size()));
  }
  std::string frame;
  frame.reserve(payload.size() + 4);
  const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
  for (int i = 0; i < 4; ++i) frame.push_back(static_cast<char>((length >> (i * 8)) & 0xFFu));
  frame.append(payload);
  return send_all(frame);
}

std::uint16_t Socket::local_port() const noexcept {
  if (handle_ == -1) return 0;
  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  if (::getsockname(static_cast<NativeHandle>(handle_), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return 0;
  }
  if (storage.ss_family == AF_INET) {
    const auto* address = reinterpret_cast<const sockaddr_in*>(&storage);
    return ntohs(address->sin_port);
  }
  if (storage.ss_family == AF_INET6) {
    const auto* address = reinterpret_cast<const sockaddr_in6*>(&storage);
    return ntohs(address->sin6_port);
  }
  return 0;
}

std::uint16_t Socket::peer_port() const noexcept {
  if (handle_ == -1) return 0;
  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  if (::getpeername(static_cast<NativeHandle>(handle_), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return 0;
  }
  if (storage.ss_family == AF_INET) {
    const auto* address = reinterpret_cast<const sockaddr_in*>(&storage);
    return ntohs(address->sin_port);
  }
  return 0;
}

std::string Socket::peer_address() const {
  if (handle_ == -1) return {};
  sockaddr_storage storage{};
  socklen_t length = sizeof(storage);
  if (::getpeername(static_cast<NativeHandle>(handle_), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
    return {};
  }
  char buffer[INET6_ADDRSTRLEN];
  std::memset(buffer, 0, sizeof(buffer));
  if (storage.ss_family == AF_INET) {
    const auto* address = reinterpret_cast<const sockaddr_in*>(&storage);
    ::inet_ntop(AF_INET, &address->sin_addr, buffer, sizeof(buffer));
  } else if (storage.ss_family == AF_INET6) {
    const auto* address = reinterpret_cast<const sockaddr_in6*>(&storage);
    ::inet_ntop(AF_INET6, &address->sin6_addr, buffer, sizeof(buffer));
  }
  return std::string(buffer);
}

}  // namespace gpf::net
