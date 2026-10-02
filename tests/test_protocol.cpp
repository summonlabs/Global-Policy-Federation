#include "fixtures.hpp"
#include "gpf/net.hpp"
#include "gpf/protocol.hpp"
#include "test_support.hpp"

#include <string>
#include <thread>

using namespace gpf;
using namespace gpf_test;

namespace {

std::string frame_with_declared_length(std::uint32_t declared, const std::string& payload) {
  std::string frame;
  for (int i = 0; i < 4; ++i) frame.push_back(static_cast<char>((declared >> (i * 8)) & 0xFFu));
  frame.append(payload);
  return frame;
}

}  // namespace

GPF_TEST(protocol, envelope_round_trips_and_rejects_malformed_frames) {
  Envelope envelope = make_envelope(MessageType::SyncRequest, SequenceNumber{7},
                                    sync_request_to_json(SyncRequestMessage{Generation{3}, Digest{}}));
  envelope.reply_to = SequenceNumber{4};
  const std::string frame = encode_frame(envelope);

  auto decoded = decode_frame(frame);
  if (!decoded.ok()) NOTE("decode failed: " + decoded.error.to_string());
  REQUIRE(decoded.ok());
  CHECK(decoded->type == MessageType::SyncRequest);
  CHECK_EQ(decoded->id.value, std::uint64_t{7});
  CHECK_EQ(decoded->reply_to.value, std::uint64_t{4});
  auto request = sync_request_from_json(decoded->body);
  REQUIRE(request.ok());
  CHECK_EQ(request->applied_global_generation.value, std::uint64_t{3});

  // Declared length that does not match the payload.
  CHECK(!decode_frame(frame_with_declared_length(4, "{}")).ok());
  // Truncated frame.
  CHECK(!decode_frame(frame.substr(0, frame.size() - 5)).ok());
  CHECK(!decode_frame("").ok());
  CHECK(!decode_frame("abc").ok());
  // Body that is not JSON, or not an object.
  CHECK(!decode_frame(frame_with_declared_length(3, "[]x")).ok());
  CHECK(!decode_frame(frame_with_declared_length(2, "[]")).ok());
  // Unknown message type.
  CHECK(!decode_frame(frame_with_declared_length(
                          static_cast<std::uint32_t>(std::string(R"({"v":1,"type":"teleport","id":1,"reply_to":0,"body":{}})").size()),
                          R"({"v":1,"type":"teleport","id":1,"reply_to":0,"body":{}})"))
             .ok());
  // Unsupported protocol version is refused rather than parsed optimistically.
  const std::string future_version = R"({"v":99,"type":"hello","id":1,"reply_to":0,"body":{}})";
  CHECK(!decode_frame(frame_with_declared_length(static_cast<std::uint32_t>(future_version.size()),
                                                 future_version))
             .ok());
  // Duplicate keys inside the envelope are refused by the JSON reader.
  const std::string duplicated =
      R"({"v":1,"v":1,"type":"hello","id":1,"reply_to":0,"body":{}})";
  CHECK(!decode_frame(frame_with_declared_length(static_cast<std::uint32_t>(duplicated.size()), duplicated)).ok());
}

GPF_TEST(protocol, absurd_declared_lengths_are_refused_before_allocation) {
  const std::string hostile = frame_with_declared_length(0xFFFFFFFFu, "tiny");
  auto decoded = decode_frame(hostile);
  CHECK(!decoded.ok());
  // The declared length is refused on the length check, not by trying to build a 4 GiB string.
  CHECK_EQ(error_code_name(decoded.error.code), std::string("malformed-input"));
}

GPF_TEST(protocol, message_bodies_are_validated_as_untrusted_input) {
  auto hello = JsonValue::parse(hello_to_json(HelloMessage{}).dump());
  REQUIRE(hello.ok());
  // A nil federation identity is structurally valid JSON but not a usable handshake.
  auto parsed_hello = hello_from_json(*hello);
  CHECK(parsed_hello.ok());
  hello->set_field("federation", JsonValue::text("not-an-identity"));
  CHECK(!hello_from_json(*hello).ok());
  hello->set_field("federation", JsonValue::integer(4));
  CHECK(!hello_from_json(*hello).ok());

  // Receipt arrays are bounded before they are walked.
  JsonValue::Array receipts;
  for (std::size_t i = 0; i < 4; ++i) receipts.push_back(receipt_to_json(Receipt{}));
  ReceiptReportMessage report;
  report.receipts.push_back(Receipt{});
  JsonValue report_json = receipt_report_to_json(report);
  std::size_t oversized = limits::kMaxReceiptsPerSite + 1;
  JsonValue::Array big;
  big.reserve(oversized);
  for (std::size_t i = 0; i < oversized; ++i) big.push_back(receipts[0]);
  report_json.set_field("receipts", JsonValue::array(std::move(big)));
  auto parsed_report = receipt_report_from_json(report_json);
  CHECK(!parsed_report.ok());
  CHECK_EQ(error_code_name(parsed_report.error.code), std::string("too-large"));
}

GPF_TEST(protocol, sockets_carry_frames_and_report_disconnects) {
  net::ensure_initialized();
  auto listener = net::Socket::listen("127.0.0.1", 0);
  if (!listener.ok()) NOTE("listen failed: " + listener.error.to_string());
  REQUIRE(listener.ok());
  const std::uint16_t port = listener->local_port();
  CHECK(port != 0);

  std::thread server([&] {
    auto accepted = listener->accept();
    if (!accepted.ok()) return;
    auto frame = accepted->receive_frame(limits::kMaxWireMessageBytes);
    if (!frame.ok()) return;
    auto envelope = decode_frame(*frame);
    if (!envelope.ok()) return;
    HelloMessage hello;
    hello.federation.value = IdGenerator(1).next();
    (void)accepted->send_frame(encode_frame(
        make_envelope(MessageType::Welcome, SequenceNumber{1}, welcome_to_json(WelcomeMessage{}))));
    (void)accepted->send_frame(encode_frame(make_envelope(
        MessageType::Ack, SequenceNumber{2}, ack_to_json(AckMessage{}))));
    // Send a frame the peer never declares it can read, to prove the bound is enforced on receive.
    (void)accepted->send_frame(std::string(64, 'x'));
    accepted->close();
  });

  auto client = net::Socket::connect("127.0.0.1", port);
  if (!client.ok()) NOTE("connect failed: " + client.error.to_string());
  REQUIRE(client.ok());
  REQUIRE(client->send_frame(encode_frame(make_envelope(MessageType::Hello, SequenceNumber{1},
                                                        hello_to_json(HelloMessage{}))))
              .ok());
  auto welcome = client->receive_frame(limits::kMaxWireMessageBytes);
  REQUIRE(welcome.ok());
  auto welcome_envelope = decode_frame(*welcome);
  REQUIRE(welcome_envelope.ok());
  CHECK(welcome_envelope->type == MessageType::Welcome);

  // A frame larger than the caller's bound is refused, not buffered.
  auto bounded = client->receive_frame(8);
  CHECK(!bounded.ok());
  CHECK_EQ(error_code_name(bounded.error.code), std::string("too-large"));

  // The refused frame closed the connection, so the next read reports the disconnect instead of
  // interpreting the unread payload as a new header.
  auto closed = client->receive_frame(limits::kMaxWireMessageBytes);
  CHECK(!closed.ok());
  CHECK_EQ(error_code_name(closed.error.code), std::string("not-connected"));
  CHECK(!client->is_open());
  client->close();
  server.join();
  listener->close();
}

GPF_TEST(protocol, host_validation_refuses_injection_shaped_addresses) {
  CHECK(net::is_valid_host("127.0.0.1"));
  CHECK(net::is_valid_host("localhost"));
  CHECK(net::is_valid_host("::1"));
  CHECK(!net::is_valid_host(""));
  CHECK(!net::is_valid_host("host; rm -rf /"));
  CHECK(!net::is_valid_host("host name"));
  CHECK(!net::is_valid_host("../../etc/passwd"));
  CHECK(!net::is_valid_host(std::string("a") + '\n' + "b"));
  CHECK(!net::is_valid_host(std::string(200, 'a')));
}
