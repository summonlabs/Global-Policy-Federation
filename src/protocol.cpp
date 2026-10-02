#include "gpf/protocol.hpp"

#include <algorithm>

namespace gpf {
namespace {

template <class IdType>
Result<IdType> id_field(const JsonValue& value, const char* key) {
  auto text = value.require_string(key);
  if (!text) return Result<IdType>::failure(text.error);
  return IdType::parse(*text);
}

Result<Digest> digest_field(const JsonValue& value, const char* key) {
  auto text = value.require_string(key);
  if (!text) return Result<Digest>::failure(text.error);
  return Digest::from_hex(*text);
}

Result<Generation> generation_field(const JsonValue& value, const char* key) {
  auto raw = value.require_int_in_range(key, 0, INT64_MAX);
  if (!raw) return Result<Generation>::failure(raw.error);
  if (static_cast<std::uint64_t>(*raw) > limits::kMaxGenerationValue) {
    return Result<Generation>::failure(ErrorCode::Overflow, "generation is out of range", key);
  }
  return Result<Generation>::success(Generation{static_cast<std::uint64_t>(*raw)});
}

Result<SequenceNumber> sequence_field(const JsonValue& value, const char* key) {
  auto raw = value.require_int_in_range(key, 0, INT64_MAX);
  if (!raw) return Result<SequenceNumber>::failure(raw.error);
  return Result<SequenceNumber>::success(SequenceNumber{static_cast<std::uint64_t>(*raw)});
}

Result<Epoch> epoch_field(const JsonValue& value, const char* key) {
  auto raw = value.require_int_in_range(key, 0, INT64_MAX);
  if (!raw) return Result<Epoch>::failure(raw.error);
  return Result<Epoch>::success(Epoch{static_cast<std::uint64_t>(*raw)});
}

Result<SemanticVersion> version_field(const JsonValue& value, const char* key) {
  auto text = value.require_string(key);
  if (!text) return Result<SemanticVersion>::failure(text.error);
  return SemanticVersion::parse(*text);
}

// Bundles, revocations and grants share one bounded array reader.
template <class T, class Decode>
Result<std::vector<T>> decode_array(const JsonValue& value, const char* key, std::size_t limit,
                                    Decode decode) {
  auto items = value.require_array(key);
  if (!items) return Result<std::vector<T>>::failure(items.error);
  if ((*items)->size() > limit) {
    return Result<std::vector<T>>::failure(ErrorCode::TooLarge, "array exceeds the message limit", key);
  }
  std::vector<T> out;
  out.reserve((*items)->size());
  for (const JsonValue& item : (*items)->array_items()) {
    auto decoded = decode(item);
    if (!decoded) return Result<std::vector<T>>::failure(decoded.error);
    out.push_back(std::move(*decoded.value));
  }
  return Result<std::vector<T>>::success(std::move(out));
}

template <class T, class Encode>
JsonValue encode_array(const std::vector<T>& items, Encode encode) {
  JsonValue::Array array;
  array.reserve(items.size());
  for (const T& item : items) array.push_back(encode(item));
  return JsonValue::array(std::move(array));
}

}  // namespace

const char* message_type_name(MessageType type) noexcept {
  switch (type) {
    case MessageType::Hello: return "hello";
    case MessageType::Welcome: return "welcome";
    case MessageType::SyncRequest: return "sync-request";
    case MessageType::SyncResponse: return "sync-response";
    case MessageType::PolicyUpdate: return "policy-update";
    case MessageType::ReceiptReport: return "receipt-report";
    case MessageType::OverrideReport: return "override-report";
    case MessageType::Ack: return "ack";
    case MessageType::ErrorReport: return "error";
    case MessageType::Shutdown: return "shutdown";
  }
  return "unknown";
}

Result<MessageType> message_type_from_name(std::string_view name) {
  for (std::uint8_t raw = 1; raw <= 10; ++raw) {
    const auto type = static_cast<MessageType>(raw);
    if (name == message_type_name(type)) return Result<MessageType>::success(type);
  }
  return Result<MessageType>::failure(ErrorCode::MalformedInput, "unknown message type",
                                      escape_preview(name));
}

Envelope make_envelope(MessageType type, SequenceNumber id, JsonValue body) {
  Envelope envelope;
  envelope.protocol_version = kProtocolVersion;
  envelope.type = type;
  envelope.id = id;
  envelope.body = std::move(body);
  return envelope;
}

Envelope make_ack(SequenceNumber id, SequenceNumber reply_to, const AckMessage& message) {
  Envelope envelope = make_envelope(MessageType::Ack, id, ack_to_json(message));
  envelope.reply_to = reply_to;
  return envelope;
}

std::string encode_frame(const Envelope& envelope) {
  JsonValue object = JsonValue::object({
      {"v", JsonValue::integer(static_cast<std::int64_t>(envelope.protocol_version))},
      {"type", JsonValue::text(message_type_name(envelope.type))},
      {"id", JsonValue::integer(static_cast<std::int64_t>(envelope.id.value))},
      {"reply_to", JsonValue::integer(static_cast<std::int64_t>(envelope.reply_to.value))},
      {"body", envelope.body},
  });
  const std::string payload = object.dump(true);
  std::string frame;
  frame.reserve(payload.size() + 4);
  const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
  for (int i = 0; i < 4; ++i) frame.push_back(static_cast<char>((length >> (i * 8)) & 0xFFu));
  frame.append(payload);
  return frame;
}

Result<Envelope> decode_frame(std::string_view frame) {
  if (frame.size() < 4) return Result<Envelope>::failure(ErrorCode::MalformedInput, "frame is too short");
  std::uint32_t declared = 0;
  for (int i = 0; i < 4; ++i) {
    declared |= static_cast<std::uint32_t>(static_cast<unsigned char>(frame[static_cast<std::size_t>(i)]))
                << (i * 8);
  }
  const std::string_view payload = frame.substr(4);
  if (declared != payload.size()) {
    return Result<Envelope>::failure(ErrorCode::MalformedInput, "frame length does not match its payload",
                                     std::to_string(declared) + " vs " + std::to_string(payload.size()));
  }
  if (payload.size() > kMaxFrameBytes) {
    return Result<Envelope>::failure(ErrorCode::TooLarge, "frame exceeds the size limit");
  }
  auto parsed = JsonValue::parse(payload);
  if (!parsed) return Result<Envelope>::failure(parsed.error);
  if (!parsed->is_object()) {
    return Result<Envelope>::failure(ErrorCode::MalformedInput, "frame body is not an object");
  }
  auto version = parsed->require_int_in_range("v", 1, 1000);
  if (!version) return Result<Envelope>::failure(version.error);
  if (static_cast<std::uint32_t>(*version) != kProtocolVersion) {
    return Result<Envelope>::failure(ErrorCode::UnsupportedFormat, "unsupported protocol version",
                                     std::to_string(*version));
  }
  auto type_name = parsed->require_string("type");
  if (!type_name) return Result<Envelope>::failure(type_name.error);
  auto type = message_type_from_name(*type_name);
  if (!type) return Result<Envelope>::failure(type.error);
  auto id = sequence_field(*parsed, "id");
  if (!id) return Result<Envelope>::failure(id.error);
  auto reply_to = sequence_field(*parsed, "reply_to");
  if (!reply_to) return Result<Envelope>::failure(reply_to.error);
  auto body = parsed->require_object("body");
  if (!body) return Result<Envelope>::failure(body.error);
  Envelope envelope;
  envelope.protocol_version = static_cast<std::uint32_t>(*version);
  envelope.type = *type;
  envelope.id = *id;
  envelope.reply_to = *reply_to;
  envelope.body = **body;
  return Result<Envelope>::success(std::move(envelope));
}

// ---------------------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------------------

JsonValue hello_to_json(const HelloMessage& message) {
  return JsonValue::object({
      {"federation", JsonValue::text(message.federation.to_string())},
      {"member", JsonValue::text(message.member.to_string())},
      {"site", JsonValue::text(message.site.to_string())},
      {"site_epoch", JsonValue::integer(static_cast<std::int64_t>(message.site_epoch.value))},
      {"local_generation", JsonValue::integer(static_cast<std::int64_t>(message.local_generation.value))},
      {"applied_global_generation",
       JsonValue::integer(static_cast<std::int64_t>(message.applied_global_generation.value))},
      {"applied_policy_digest", JsonValue::text(message.applied_policy_digest.to_hex())},
      {"runtime_version", JsonValue::text(message.runtime_version.to_string())},
      {"capabilities", capability_snapshot_to_json(message.capabilities)},
      {"membership_digest", JsonValue::text(message.membership_digest.to_hex())},
  });
}

Result<HelloMessage> hello_from_json(const JsonValue& value) {
  HelloMessage message;
  auto federation = id_field<FederationId>(value, "federation");
  if (!federation) return Result<HelloMessage>::failure(federation.error);
  message.federation = *federation;
  auto member = id_field<MemberId>(value, "member");
  if (!member) return Result<HelloMessage>::failure(member.error);
  message.member = *member;
  auto site = id_field<SiteId>(value, "site");
  if (!site) return Result<HelloMessage>::failure(site.error);
  message.site = *site;
  auto epoch = epoch_field(value, "site_epoch");
  if (!epoch) return Result<HelloMessage>::failure(epoch.error);
  message.site_epoch = *epoch;
  auto local = generation_field(value, "local_generation");
  if (!local) return Result<HelloMessage>::failure(local.error);
  message.local_generation = *local;
  auto applied = generation_field(value, "applied_global_generation");
  if (!applied) return Result<HelloMessage>::failure(applied.error);
  message.applied_global_generation = *applied;
  auto digest = digest_field(value, "applied_policy_digest");
  if (!digest) return Result<HelloMessage>::failure(digest.error);
  message.applied_policy_digest = *digest;
  auto runtime = version_field(value, "runtime_version");
  if (!runtime) return Result<HelloMessage>::failure(runtime.error);
  message.runtime_version = *runtime;
  auto capabilities = value.require_object("capabilities");
  if (!capabilities) return Result<HelloMessage>::failure(capabilities.error);
  auto parsed_capabilities = capability_snapshot_from_json(**capabilities);
  if (!parsed_capabilities) return Result<HelloMessage>::failure(parsed_capabilities.error);
  message.capabilities = std::move(*parsed_capabilities.value);
  auto membership = digest_field(value, "membership_digest");
  if (!membership) return Result<HelloMessage>::failure(membership.error);
  message.membership_digest = *membership;
  return Result<HelloMessage>::success(std::move(message));
}

JsonValue welcome_to_json(const WelcomeMessage& message) {
  return JsonValue::object({
      {"federation", JsonValue::text(message.federation.to_string())},
      {"authority_epoch", JsonValue::integer(static_cast<std::int64_t>(message.authority_epoch.value))},
      {"global_generation", JsonValue::integer(static_cast<std::int64_t>(message.global_generation.value))},
      {"session", JsonValue::integer(static_cast<std::int64_t>(message.session.value))},
      {"has_catalog", JsonValue::boolean(message.has_catalog)},
      {"catalog", capability_catalog_to_json(message.catalog)},
  });
}

Result<WelcomeMessage> welcome_from_json(const JsonValue& value) {
  WelcomeMessage message;
  auto federation = id_field<FederationId>(value, "federation");
  if (!federation) return Result<WelcomeMessage>::failure(federation.error);
  message.federation = *federation;
  auto epoch = epoch_field(value, "authority_epoch");
  if (!epoch) return Result<WelcomeMessage>::failure(epoch.error);
  message.authority_epoch = *epoch;
  auto generation = generation_field(value, "global_generation");
  if (!generation) return Result<WelcomeMessage>::failure(generation.error);
  message.global_generation = *generation;
  auto session = sequence_field(value, "session");
  if (!session) return Result<WelcomeMessage>::failure(session.error);
  message.session = *session;
  auto has_catalog = value.require_bool("has_catalog");
  if (!has_catalog) return Result<WelcomeMessage>::failure(has_catalog.error);
  message.has_catalog = *has_catalog;
  auto catalog = value.require_object("catalog");
  if (!catalog) return Result<WelcomeMessage>::failure(catalog.error);
  auto parsed_catalog = capability_catalog_from_json(**catalog);
  if (!parsed_catalog) return Result<WelcomeMessage>::failure(parsed_catalog.error);
  message.catalog = std::move(*parsed_catalog.value);
  return Result<WelcomeMessage>::success(std::move(message));
}

JsonValue sync_request_to_json(const SyncRequestMessage& message) {
  return JsonValue::object({
      {"applied_global_generation",
       JsonValue::integer(static_cast<std::int64_t>(message.applied_global_generation.value))},
      {"applied_policy_digest", JsonValue::text(message.applied_policy_digest.to_hex())},
  });
}

Result<SyncRequestMessage> sync_request_from_json(const JsonValue& value) {
  SyncRequestMessage message;
  auto applied = generation_field(value, "applied_global_generation");
  if (!applied) return Result<SyncRequestMessage>::failure(applied.error);
  message.applied_global_generation = *applied;
  auto digest = digest_field(value, "applied_policy_digest");
  if (!digest) return Result<SyncRequestMessage>::failure(digest.error);
  message.applied_policy_digest = *digest;
  return Result<SyncRequestMessage>::success(std::move(message));
}

JsonValue policy_update_to_json(const PolicyUpdateMessage& message) {
  return JsonValue::object({
      {"bundles", encode_array(message.bundles, [](const PolicyBundle& bundle) {
         return bundle_to_json(bundle);
       })},
      {"revocations", encode_array(message.revocations, [](const RevocationRecord& record) {
         return revocation_to_json(record);
       })},
      {"grants", encode_array(message.grants, [](const AuthorityGrant& grant) {
         return grant_to_json(grant);
       })},
      {"has_catalog", JsonValue::boolean(message.has_catalog)},
      {"catalog", capability_catalog_to_json(message.catalog)},
  });
}

Result<PolicyUpdateMessage> policy_update_from_json(const JsonValue& value) {
  PolicyUpdateMessage message;
  auto bundles = decode_array<PolicyBundle>(value, "bundles", limits::kMaxBundlesPerFederation,
                                            [](const JsonValue& item) { return bundle_from_json(item); });
  if (!bundles) return Result<PolicyUpdateMessage>::failure(bundles.error);
  message.bundles = std::move(*bundles.value);
  auto revocations = decode_array<RevocationRecord>(
      value, "revocations", limits::kMaxRevocations,
      [](const JsonValue& item) { return revocation_from_json(item); });
  if (!revocations) return Result<PolicyUpdateMessage>::failure(revocations.error);
  message.revocations = std::move(*revocations.value);
  auto grants = decode_array<AuthorityGrant>(value, "grants", limits::kMaxGrantsPerFederation,
                                             [](const JsonValue& item) { return grant_from_json(item); });
  if (!grants) return Result<PolicyUpdateMessage>::failure(grants.error);
  message.grants = std::move(*grants.value);
  auto has_catalog = value.require_bool("has_catalog");
  if (!has_catalog) return Result<PolicyUpdateMessage>::failure(has_catalog.error);
  message.has_catalog = *has_catalog;
  auto catalog = value.require_object("catalog");
  if (!catalog) return Result<PolicyUpdateMessage>::failure(catalog.error);
  auto parsed_catalog = capability_catalog_from_json(**catalog);
  if (!parsed_catalog) return Result<PolicyUpdateMessage>::failure(parsed_catalog.error);
  message.catalog = std::move(*parsed_catalog.value);
  return Result<PolicyUpdateMessage>::success(std::move(message));
}

JsonValue sync_response_to_json(const SyncResponseMessage& message) {
  return JsonValue::object({
      {"bundles", encode_array(message.bundles, [](const PolicyBundle& bundle) {
         return bundle_to_json(bundle);
       })},
      {"revocations", encode_array(message.revocations, [](const RevocationRecord& record) {
         return revocation_to_json(record);
       })},
      {"grants", encode_array(message.grants, [](const AuthorityGrant& grant) {
         return grant_to_json(grant);
       })},
      {"has_catalog", JsonValue::boolean(message.has_catalog)},
      {"catalog", capability_catalog_to_json(message.catalog)},
      {"complete", JsonValue::boolean(message.complete)},
      {"current_generation", JsonValue::integer(static_cast<std::int64_t>(message.current_generation.value))},
  });
}

Result<SyncResponseMessage> sync_response_from_json(const JsonValue& value) {
  SyncResponseMessage message;
  auto bundles = decode_array<PolicyBundle>(value, "bundles", limits::kMaxBundlesPerFederation,
                                            [](const JsonValue& item) { return bundle_from_json(item); });
  if (!bundles) return Result<SyncResponseMessage>::failure(bundles.error);
  message.bundles = std::move(*bundles.value);
  auto revocations = decode_array<RevocationRecord>(
      value, "revocations", limits::kMaxRevocations,
      [](const JsonValue& item) { return revocation_from_json(item); });
  if (!revocations) return Result<SyncResponseMessage>::failure(revocations.error);
  message.revocations = std::move(*revocations.value);
  auto grants = decode_array<AuthorityGrant>(value, "grants", limits::kMaxGrantsPerFederation,
                                             [](const JsonValue& item) { return grant_from_json(item); });
  if (!grants) return Result<SyncResponseMessage>::failure(grants.error);
  message.grants = std::move(*grants.value);
  auto has_catalog = value.require_bool("has_catalog");
  if (!has_catalog) return Result<SyncResponseMessage>::failure(has_catalog.error);
  message.has_catalog = *has_catalog;
  auto catalog = value.require_object("catalog");
  if (!catalog) return Result<SyncResponseMessage>::failure(catalog.error);
  auto parsed_catalog = capability_catalog_from_json(**catalog);
  if (!parsed_catalog) return Result<SyncResponseMessage>::failure(parsed_catalog.error);
  message.catalog = std::move(*parsed_catalog.value);
  auto complete = value.require_bool("complete");
  if (!complete) return Result<SyncResponseMessage>::failure(complete.error);
  message.complete = *complete;
  auto generation = generation_field(value, "current_generation");
  if (!generation) return Result<SyncResponseMessage>::failure(generation.error);
  message.current_generation = *generation;
  return Result<SyncResponseMessage>::success(std::move(message));
}

JsonValue receipt_report_to_json(const ReceiptReportMessage& message) {
  return JsonValue::object({
      {"receipts", encode_array(message.receipts, [](const Receipt& receipt) {
         return receipt_to_json(receipt);
       })},
      {"replay", JsonValue::boolean(message.replay)},
  });
}

Result<ReceiptReportMessage> receipt_report_from_json(const JsonValue& value) {
  ReceiptReportMessage message;
  auto receipts = decode_array<Receipt>(value, "receipts", limits::kMaxReceiptsPerSite,
                                        [](const JsonValue& item) { return receipt_from_json(item); });
  if (!receipts) return Result<ReceiptReportMessage>::failure(receipts.error);
  message.receipts = std::move(*receipts.value);
  auto replay = value.require_bool("replay");
  if (!replay) return Result<ReceiptReportMessage>::failure(replay.error);
  message.replay = *replay;
  return Result<ReceiptReportMessage>::success(std::move(message));
}

JsonValue override_report_to_json(const OverrideReportMessage& message) {
  return JsonValue::object({
      {"override", override_to_json(message.override_record)},
      {"outcome_code", JsonValue::text(message.outcome_code)},
      {"outcome_detail", JsonValue::text(message.outcome_detail)},
  });
}

Result<OverrideReportMessage> override_report_from_json(const JsonValue& value) {
  OverrideReportMessage message;
  auto override_json = value.require_object("override");
  if (!override_json) return Result<OverrideReportMessage>::failure(override_json.error);
  auto parsed = override_from_json(**override_json);
  if (!parsed) return Result<OverrideReportMessage>::failure(parsed.error);
  message.override_record = std::move(*parsed.value);
  auto code = value.require_string("outcome_code");
  if (!code) return Result<OverrideReportMessage>::failure(code.error);
  message.outcome_code = *code;
  auto detail = value.require_string("outcome_detail");
  if (!detail) return Result<OverrideReportMessage>::failure(detail.error);
  message.outcome_detail = *detail;
  return Result<OverrideReportMessage>::success(std::move(message));
}

JsonValue ack_to_json(const AckMessage& message) {
  return JsonValue::object({
      {"request_id", JsonValue::integer(static_cast<std::int64_t>(message.request_id.value))},
      {"reason_code", JsonValue::text(message.reason_code)},
      {"detail", JsonValue::text(message.detail)},
      {"accepted", JsonValue::boolean(message.accepted)},
  });
}

Result<AckMessage> ack_from_json(const JsonValue& value) {
  AckMessage message;
  auto request = sequence_field(value, "request_id");
  if (!request) return Result<AckMessage>::failure(request.error);
  message.request_id = *request;
  auto reason = value.require_string("reason_code");
  if (!reason) return Result<AckMessage>::failure(reason.error);
  message.reason_code = *reason;
  auto detail = value.require_string("detail");
  if (!detail) return Result<AckMessage>::failure(detail.error);
  message.detail = *detail;
  auto accepted = value.require_bool("accepted");
  if (!accepted) return Result<AckMessage>::failure(accepted.error);
  message.accepted = *accepted;
  return Result<AckMessage>::success(std::move(message));
}

JsonValue error_to_json(const ErrorMessage& message) {
  return JsonValue::object({
      {"code", JsonValue::text(message.code)},
      {"detail", JsonValue::text(message.detail)},
      {"request_id", JsonValue::integer(static_cast<std::int64_t>(message.request_id.value))},
  });
}

Result<ErrorMessage> error_from_json(const JsonValue& value) {
  ErrorMessage message;
  auto code = value.require_string("code");
  if (!code) return Result<ErrorMessage>::failure(code.error);
  message.code = *code;
  auto detail = value.require_string("detail");
  if (!detail) return Result<ErrorMessage>::failure(detail.error);
  message.detail = *detail;
  auto request = sequence_field(value, "request_id");
  if (!request) return Result<ErrorMessage>::failure(request.error);
  message.request_id = *request;
  return Result<ErrorMessage>::success(std::move(message));
}

JsonValue shutdown_to_json(const ShutdownMessage& message) {
  return JsonValue::object({{"reason", JsonValue::text(message.reason)}});
}

Result<ShutdownMessage> shutdown_from_json(const JsonValue& value) {
  ShutdownMessage message;
  auto reason = value.require_string("reason");
  if (!reason) return Result<ShutdownMessage>::failure(reason.error);
  message.reason = *reason;
  return Result<ShutdownMessage>::success(std::move(message));
}

}  // namespace gpf
