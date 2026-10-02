#pragma once
// Global Policy Federation — federation wire protocol.
//
// Framing: a little-endian 32-bit length followed by one JSON envelope. Both directions are
// bounded before allocation, every message is validated before use, and the protocol version is
// part of the envelope so a peer that speaks a different contract is refused explicitly rather
// than parsed optimistically.

#include "gpf/authority.hpp"
#include "gpf/base.hpp"
#include "gpf/codec.hpp"
#include "gpf/effective.hpp"
#include "gpf/policy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace gpf {

inline constexpr std::uint32_t kProtocolVersion = 1;
inline constexpr std::size_t kMaxFrameBytes = limits::kMaxWireMessageBytes;

enum class MessageType : std::uint8_t {
  Hello = 1,
  Welcome = 2,
  SyncRequest = 3,
  SyncResponse = 4,
  PolicyUpdate = 5,
  ReceiptReport = 6,
  OverrideReport = 7,
  Ack = 8,
  ErrorReport = 9,
  Shutdown = 10,
};

const char* message_type_name(MessageType type) noexcept;
Result<MessageType> message_type_from_name(std::string_view name);

struct Envelope {
  std::uint32_t protocol_version{kProtocolVersion};
  MessageType type{MessageType::Hello};
  SequenceNumber id{};
  SequenceNumber reply_to{};
  JsonValue body{JsonValue::object()};
};

// Encodes one envelope. The result is the complete frame, ready to send.
std::string encode_frame(const Envelope& envelope);
// Decodes one frame. Fails on a short, oversized, malformed or unsupported frame.
Result<Envelope> decode_frame(std::string_view frame);

// ---------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------

struct HelloMessage {
  FederationId federation;
  MemberId member;
  SiteId site;
  Epoch site_epoch{};
  Generation local_generation{};
  Generation applied_global_generation{};
  Digest applied_policy_digest{};
  SemanticVersion runtime_version{};
  SiteCapabilitySnapshot capabilities;
  Digest membership_digest{};
};

struct WelcomeMessage {
  FederationId federation;
  Epoch authority_epoch{};
  Generation global_generation{};
  SequenceNumber session{};
  CapabilityCatalog catalog;
  bool has_catalog{false};
};

struct SyncRequestMessage {
  Generation applied_global_generation{};
  Digest applied_policy_digest{};
};

struct PolicyUpdateMessage {
  std::vector<PolicyBundle> bundles;
  std::vector<RevocationRecord> revocations;
  std::vector<AuthorityGrant> grants;
  CapabilityCatalog catalog;
  bool has_catalog{false};
};

struct SyncResponseMessage {
  std::vector<PolicyBundle> bundles;
  std::vector<RevocationRecord> revocations;
  std::vector<AuthorityGrant> grants;
  CapabilityCatalog catalog;
  bool has_catalog{false};
  // A partial answer is explicitly marked: the site must not treat it as a complete view.
  bool complete{true};
  Generation current_generation{};
};

struct ReceiptReportMessage {
  std::vector<Receipt> receipts;
  // Receipts the site could not send before are replayed in order, so the federation sees every
  // decision exactly once even across a partition.
  bool replay{false};
};

struct OverrideReportMessage {
  LocalOverride override_record{};
  std::string outcome_code;
  std::string outcome_detail;
};

struct AckMessage {
  // Echoes the acknowledged request. For a receipt report, request_id carries the number of
  // receipts the federation accepted and recorded, so the site can drop exactly those.
  SequenceNumber request_id{};
  std::string reason_code;
  std::string detail;
  bool accepted{true};
};

struct ErrorMessage {
  std::string code;
  std::string detail;
  SequenceNumber request_id{};
};

struct ShutdownMessage {
  std::string reason;
};

JsonValue hello_to_json(const HelloMessage& message);
Result<HelloMessage> hello_from_json(const JsonValue& value);
JsonValue welcome_to_json(const WelcomeMessage& message);
Result<WelcomeMessage> welcome_from_json(const JsonValue& value);
JsonValue sync_request_to_json(const SyncRequestMessage& message);
Result<SyncRequestMessage> sync_request_from_json(const JsonValue& value);
JsonValue policy_update_to_json(const PolicyUpdateMessage& message);
Result<PolicyUpdateMessage> policy_update_from_json(const JsonValue& value);
JsonValue sync_response_to_json(const SyncResponseMessage& message);
Result<SyncResponseMessage> sync_response_from_json(const JsonValue& value);
JsonValue receipt_report_to_json(const ReceiptReportMessage& message);
Result<ReceiptReportMessage> receipt_report_from_json(const JsonValue& value);
JsonValue override_report_to_json(const OverrideReportMessage& message);
Result<OverrideReportMessage> override_report_from_json(const JsonValue& value);
JsonValue ack_to_json(const AckMessage& message);
Result<AckMessage> ack_from_json(const JsonValue& value);
JsonValue error_to_json(const ErrorMessage& message);
Result<ErrorMessage> error_from_json(const JsonValue& value);
JsonValue shutdown_to_json(const ShutdownMessage& message);
Result<ShutdownMessage> shutdown_from_json(const JsonValue& value);

// Convenience constructors for typed envelopes.
Envelope make_envelope(MessageType type, SequenceNumber id, JsonValue body);
Envelope make_ack(SequenceNumber id, SequenceNumber reply_to, const AckMessage& message);

}  // namespace gpf
