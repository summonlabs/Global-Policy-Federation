#pragma once
// Global Policy Federation — deterministic codecs: SHA-256, CRC32C, canonical binary encoding
// and a bounded, duplicate-rejecting JSON reader/writer.
//
// Everything in this header is deterministic: identical inputs produce byte-identical outputs
// on every platform, which is what makes digests, receipts and persisted state comparable
// across restarts, sites and process boundaries.

#include "gpf/base.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gpf {

// ---------------------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------------------

struct Digest {
  std::array<std::uint8_t, 32> bytes{};

  bool is_zero() const noexcept;
  std::string to_hex() const;
  static Result<Digest> from_hex(std::string_view text);

  friend bool operator==(const Digest&, const Digest&) noexcept = default;
  friend std::strong_ordering operator<=>(const Digest&, const Digest&) noexcept = default;
};

class Sha256 {
 public:
  Sha256();
  void update(const void* data, std::size_t length) noexcept;
  void update(std::string_view text) noexcept;
  // Finalizes the hash. Subsequent updates are ignored and return the same digest.
  Digest finish() noexcept;

  static Digest hash(std::string_view text) noexcept;
  static Digest hash(const void* data, std::size_t length) noexcept;

 private:
  void transform(const std::uint8_t* block) noexcept;

  std::uint32_t state_[8];
  std::uint64_t bit_length_;
  std::uint8_t buffer_[64];
  std::size_t buffer_length_;
  bool finalized_;
  Digest result_;
};

// Castagnoli CRC used as the cheap per-record integrity check inside the write-ahead log.
std::uint32_t crc32c(const void* data, std::size_t length, std::uint32_t seed = 0) noexcept;

std::string hex_encode(const void* data, std::size_t length);
Result<std::vector<std::uint8_t>> hex_decode(std::string_view text, std::size_t max_bytes);

// ---------------------------------------------------------------------------------------
// Canonical binary encoding
// ---------------------------------------------------------------------------------------
//
// Digest-relevant state is encoded through this writer. Field order, widths and the explicit
// domain-separation tags are part of the interoperability contract: changing any of them
// changes every digest this boundary publishes.
class CanonicalWriter {
 public:
  CanonicalWriter& tag(std::string_view name);
  CanonicalWriter& u8(std::uint8_t value);
  CanonicalWriter& u32(std::uint32_t value);
  CanonicalWriter& u64(std::uint64_t value);
  CanonicalWriter& i64(std::int64_t value);
  CanonicalWriter& boolean(bool value);
  CanonicalWriter& str(std::string_view value);
  CanonicalWriter& raw(std::string_view bytes);
  CanonicalWriter& digest(const Digest& value);
  CanonicalWriter& id(const Id128& value);

  const std::string& buffer() const noexcept { return buffer_; }
  Digest digest() const;
  std::size_t size() const noexcept { return buffer_.size(); }

 private:
  std::string buffer_;
};

// ---------------------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------------------

class JsonValue {
 public:
  using Array = std::vector<JsonValue>;
  using Object = std::vector<std::pair<std::string, JsonValue>>;
  enum class Type { Null, Bool, Int, String, Array, Object };

  JsonValue();

  static JsonValue null();
  static JsonValue boolean(bool value);
  static JsonValue integer(std::int64_t value);
  static JsonValue text(std::string value);
  static JsonValue array(Array values = {});
  static JsonValue object(Object fields = {});
  static JsonValue object(std::initializer_list<std::pair<std::string, JsonValue>> fields);

  Type type() const noexcept { return type_; }
  bool is_null() const noexcept { return type_ == Type::Null; }
  bool is_bool() const noexcept { return type_ == Type::Bool; }
  bool is_int() const noexcept { return type_ == Type::Int; }
  bool is_string() const noexcept { return type_ == Type::String; }
  bool is_array() const noexcept { return type_ == Type::Array; }
  bool is_object() const noexcept { return type_ == Type::Object; }

  std::size_t size() const noexcept;
  bool empty() const noexcept;

  bool as_bool() const noexcept { return type_ == Type::Bool ? bool_ : false; }
  std::int64_t as_int() const noexcept { return type_ == Type::Int ? int_ : 0; }
  const std::string& as_string() const noexcept { return string_; }
  const Array& array_items() const noexcept { return array_; }
  const Object& object_items() const noexcept { return object_; }

  // Object helpers. find() returns nullptr for absent members; a JSON null member is present
  // and reports is_null().
  const JsonValue* find(std::string_view key) const noexcept;
  bool contains(std::string_view key) const noexcept;
  void set_field(std::string key, JsonValue value);
  void push(JsonValue value);

  std::size_t node_count() const noexcept;
  bool has_valid_shape(std::size_t max_depth = limits::kMaxJsonDepth) const noexcept;

  std::string dump(bool canonical = false) const;
  static Result<JsonValue> parse(std::string_view text);

  // Typed accessors for untrusted input: each failure names the offending field.
  Result<bool> require_bool(std::string_view key) const;
  Result<std::int64_t> require_int(std::string_view key) const;
  Result<std::string> require_string(std::string_view key) const;
  Result<const JsonValue*> require_object(std::string_view key) const;
  Result<const JsonValue*> require_array(std::string_view key) const;
  Result<std::int64_t> require_int_in_range(std::string_view key, std::int64_t minimum,
                                            std::int64_t maximum) const;

 private:
  Type type_;
  bool bool_;
  std::int64_t int_;
  std::string string_;
  Array array_;
  Object object_;
};

std::string json_escape(std::string_view text);

}  // namespace gpf
