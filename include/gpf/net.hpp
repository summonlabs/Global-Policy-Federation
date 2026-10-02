#pragma once
// Global Policy Federation — TCP transport adapter.
//
// A blocking, bounded, first-party socket wrapper. There is no receive timeout anywhere in this
// project: a peer that stops talking keeps its connection until it is closed, and shutdown works
// by closing the socket rather than by racing a clock.

#include "gpf/base.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace gpf::net {

// Initializes the platform socket layer once per process.
void ensure_initialized();

class Socket {
 public:
  Socket() = default;
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  // Listening socket bound to the given address. Port zero selects an ephemeral port, which
  // local_port() reports.
  static Result<Socket> listen(const std::string& address, std::uint16_t port, int backlog = 16);
  // Outgoing connection.
  static Result<Socket> connect(const std::string& address, std::uint16_t port);
  // Accepts one connection. Returns an error on a closed listener.
  Result<Socket> accept();
  // Completes the listener's setup after accept() so a client socket is fully usable.
  Status prepare_accepted();

  Status send_all(std::string_view bytes);
  // Reads exactly one length-prefixed frame. Fails on a closed peer, a frame larger than max_bytes,
  // or a request that never completes. A protocol violation closes the connection: a stream whose
  // declared frame cannot be honored must not be interpreted further.
  Result<std::string> receive_frame(std::size_t max_bytes);
  Status send_frame(std::string_view payload);

  Status shutdown_both();
  void close();
  bool is_open() const noexcept;
  std::uint16_t local_port() const noexcept;
  std::uint16_t peer_port() const noexcept;
  std::string peer_address() const;

 private:
  std::intptr_t handle_{-1};
};

// Addresses this boundary will bind or connect to. Wildcard, loopback, and literal IPv4/IPv6
// hosts are accepted; anything else is refused before a name lookup can be abused.
bool is_valid_host(const std::string& host) noexcept;

}  // namespace gpf::net
