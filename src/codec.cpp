#include "gpf/codec.hpp"

#include <algorithm>
#include <cstring>

namespace gpf {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

inline std::uint32_t rotate_right(std::uint32_t value, unsigned bits) noexcept {
  return (value >> bits) | (value << (32u - bits));
}

std::uint32_t crc32c_table_entry(std::uint32_t index) noexcept {
  std::uint32_t crc = index;
  for (int bit = 0; bit < 8; ++bit) {
    crc = (crc & 1u) ? ((crc >> 1) ^ 0x82F63B78u) : (crc >> 1);
  }
  return crc;
}

const std::uint32_t* crc32c_table() noexcept {
  static const std::vector<std::uint32_t> table = [] {
    std::vector<std::uint32_t> values(256);
    for (std::uint32_t i = 0; i < 256; ++i) values[i] = crc32c_table_entry(i);
    return values;
  }();
  return table.data();
}

void append_hex_escaped(std::string& out, unsigned char c) {
  static const char* kHex = "0123456789abcdef";
  out += "\\u00";
  out.push_back(kHex[(c >> 4) & 0x0F]);
  out.push_back(kHex[c & 0x0F]);
}

class JsonParser {
 public:
  explicit JsonParser(std::string_view text) : text_(text) {}

  Result<JsonValue> parse() {
    if (text_.size() > limits::kMaxJsonDocumentBytes) {
      return Result<JsonValue>::failure(ErrorCode::TooLarge, "json document exceeds the size limit",
                                        std::to_string(text_.size()));
    }
    if (!is_valid_utf8(text_)) {
      return Result<JsonValue>::failure(ErrorCode::MalformedInput, "json document is not valid UTF-8",
                                        {});
    }
    skip_whitespace();
    auto value = parse_value(0);
    if (!value) return value;
    skip_whitespace();
    if (index_ != text_.size()) {
      return Result<JsonValue>::failure(ErrorCode::MalformedInput, "trailing content after json value",
                                        offset_detail());
    }
    return value;
  }

 private:
  std::string offset_detail() const { return "offset " + std::to_string(index_); }

  Result<JsonValue> fail(std::string message) const {
    return Result<JsonValue>::failure(ErrorCode::MalformedInput, std::move(message), offset_detail());
  }

  void skip_whitespace() {
    while (index_ < text_.size()) {
      const char c = text_[index_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++index_;
      } else {
        break;
      }
    }
  }

  bool consume(char expected) {
    if (index_ < text_.size() && text_[index_] == expected) {
      ++index_;
      return true;
    }
    return false;
  }

  bool consume_literal(std::string_view literal) {
    if (text_.size() - index_ >= literal.size() && text_.compare(index_, literal.size(), literal) == 0) {
      index_ += literal.size();
      return true;
    }
    return false;
  }

  Result<JsonValue> parse_value(std::size_t depth) {
    if (depth > limits::kMaxJsonDepth) {
      return Result<JsonValue>::failure(ErrorCode::LimitExceeded, "json nesting depth exceeds the limit",
                                        offset_detail());
    }
    if (++elements_ > limits::kMaxJsonElements) {
      return Result<JsonValue>::failure(ErrorCode::LimitExceeded, "json element count exceeds the limit",
                                        offset_detail());
    }
    if (index_ >= text_.size()) return fail("unexpected end of json input");
    switch (text_[index_]) {
      case '{':
        return parse_object(depth);
      case '[':
        return parse_array(depth);
      case '"': {
        std::string out;
        auto status = parse_string(out);
        if (!status.ok()) return Result<JsonValue>::failure(status.error);
        return Result<JsonValue>::success(JsonValue::text(std::move(out)));
      }
      case 't':
        if (consume_literal("true")) return Result<JsonValue>::success(JsonValue::boolean(true));
        return fail("invalid json literal");
      case 'f':
        if (consume_literal("false")) return Result<JsonValue>::success(JsonValue::boolean(false));
        return fail("invalid json literal");
      case 'n':
        if (consume_literal("null")) return Result<JsonValue>::success(JsonValue::null());
        return fail("invalid json literal");
      default:
        return parse_number();
    }
  }

  Result<JsonValue> parse_object(std::size_t depth) {
    consume('{');
    JsonValue::Object fields;
    skip_whitespace();
    if (consume('}')) return Result<JsonValue>::success(JsonValue::object(std::move(fields)));
    while (true) {
      skip_whitespace();
      if (index_ >= text_.size() || text_[index_] != '"') return fail("json object key must be a string");
      std::string key;
      auto status = parse_string(key);
      if (!status.ok()) return Result<JsonValue>::failure(status.error);
      for (const auto& existing : fields) {
        if (existing.first == key) {
          return Result<JsonValue>::failure(ErrorCode::MalformedInput, "duplicate json object key",
                                            escape_preview(key));
        }
      }
      skip_whitespace();
      if (!consume(':')) return fail("json object member needs ':'");
      skip_whitespace();
      auto value = parse_value(depth + 1);
      if (!value) return value;
      fields.emplace_back(std::move(key), std::move(*value.value));
      skip_whitespace();
      if (consume(',')) continue;
      if (consume('}')) break;
      return fail("json object member needs ',' or '}'");
    }
    return Result<JsonValue>::success(JsonValue::object(std::move(fields)));
  }

  Result<JsonValue> parse_array(std::size_t depth) {
    consume('[');
    JsonValue::Array values;
    skip_whitespace();
    if (consume(']')) return Result<JsonValue>::success(JsonValue::array(std::move(values)));
    while (true) {
      skip_whitespace();
      auto value = parse_value(depth + 1);
      if (!value) return value;
      values.push_back(std::move(*value.value));
      skip_whitespace();
      if (consume(',')) continue;
      if (consume(']')) break;
      return fail("json array element needs ',' or ']'");
    }
    return Result<JsonValue>::success(JsonValue::array(std::move(values)));
  }

  Status parse_string(std::string& out) {
    if (!consume('"')) return Status::failure(ErrorCode::MalformedInput, "expected json string", offset_detail());
    while (true) {
      if (index_ >= text_.size()) {
        return Status::failure(ErrorCode::MalformedInput, "unterminated json string", offset_detail());
      }
      const char c = text_[index_];
      if (c == '"') {
        ++index_;
        return Status::success();
      }
      if (static_cast<unsigned char>(c) < 0x20) {
        return Status::failure(ErrorCode::MalformedInput, "raw control byte inside json string",
                               offset_detail());
      }
      if (c == '\\') {
        ++index_;
        if (index_ >= text_.size()) {
          return Status::failure(ErrorCode::MalformedInput, "unterminated json escape", offset_detail());
        }
        const char escaped = text_[index_++];
        switch (escaped) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': {
            auto code_unit = [this](std::uint32_t& value) -> Status {
              if (index_ + 4 > text_.size()) {
                return Status::failure(ErrorCode::MalformedInput, "truncated json \\u escape", offset_detail());
              }
              value = 0;
              for (int i = 0; i < 4; ++i) {
                const char digit = text_[index_ + static_cast<std::size_t>(i)];
                int nibble = -1;
                if (digit >= '0' && digit <= '9') nibble = digit - '0';
                else if (digit >= 'a' && digit <= 'f') nibble = digit - 'a' + 10;
                else if (digit >= 'A' && digit <= 'F') nibble = digit - 'A' + 10;
                if (nibble < 0) {
                  return Status::failure(ErrorCode::MalformedInput, "json \\u escape is not hex",
                                         offset_detail());
                }
                value = (value << 4) | static_cast<std::uint32_t>(nibble);
              }
              index_ += 4;
              return Status::success();
            };
            std::uint32_t first = 0;
            auto status = code_unit(first);
            if (!status.ok()) return status;
            std::uint32_t code_point = first;
            if (first >= 0xD800 && first <= 0xDBFF) {
              if (index_ + 1 >= text_.size() || text_[index_] != '\\' || text_[index_ + 1] != 'u') {
                return Status::failure(ErrorCode::MalformedInput,
                                       "json high surrogate without low surrogate", offset_detail());
              }
              index_ += 2;
              std::uint32_t second = 0;
              status = code_unit(second);
              if (!status.ok()) return status;
              if (second < 0xDC00 || second > 0xDFFF) {
                return Status::failure(ErrorCode::MalformedInput, "json low surrogate is invalid",
                                       offset_detail());
              }
              code_point = 0x10000u + ((first - 0xD800u) << 10) + (second - 0xDC00u);
            } else if (first >= 0xDC00 && first <= 0xDFFF) {
              return Status::failure(ErrorCode::MalformedInput, "json lone low surrogate",
                                     offset_detail());
            }
            if (code_point < 0x80u) {
              out.push_back(static_cast<char>(code_point));
            } else if (code_point < 0x800u) {
              out.push_back(static_cast<char>(0xC0u | (code_point >> 6)));
              out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
            } else if (code_point < 0x10000u) {
              out.push_back(static_cast<char>(0xE0u | (code_point >> 12)));
              out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
              out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
            } else {
              out.push_back(static_cast<char>(0xF0u | (code_point >> 18)));
              out.push_back(static_cast<char>(0x80u | ((code_point >> 12) & 0x3Fu)));
              out.push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
              out.push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
            }
            break;
          }
          default:
            return Status::failure(ErrorCode::MalformedInput, "unknown json escape", offset_detail());
        }
      } else {
        out.push_back(c);
        ++index_;
      }
      if (out.size() > limits::kMaxJsonStringBytes) {
        return Status::failure(ErrorCode::TooLarge, "json string exceeds the size limit", offset_detail());
      }
    }
  }

  Result<JsonValue> parse_number() {
    const std::size_t start = index_;
    const bool negative = consume('-');
    if (index_ >= text_.size() || text_[index_] < '0' || text_[index_] > '9') {
      return fail("invalid json number");
    }
    if (text_[index_] == '0' && index_ + 1 < text_.size() &&
        text_[index_ + 1] >= '0' && text_[index_ + 1] <= '9') {
      return fail("json number has a leading zero");
    }
    std::uint64_t magnitude = 0;
    while (index_ < text_.size() && text_[index_] >= '0' && text_[index_] <= '9') {
      const std::uint64_t digit = static_cast<std::uint64_t>(text_[index_] - '0');
      auto scaled = checked_mul_u64(magnitude, 10);
      if (!scaled) return fail("json integer overflows 64-bit range");
      auto summed = checked_add_u64(*scaled, digit);
      if (!summed) return fail("json integer overflows 64-bit range");
      magnitude = *summed;
      ++index_;
    }
    if (index_ < text_.size() && (text_[index_] == '.' || text_[index_] == 'e' || text_[index_] == 'E')) {
      return fail("non-integer json numbers are not supported by this boundary");
    }
    if (magnitude > static_cast<std::uint64_t>(INT64_MAX) + (negative ? 1u : 0u)) {
      return fail("json integer overflows 64-bit range");
    }
    std::int64_t value = 0;
    if (negative) {
      value = magnitude == static_cast<std::uint64_t>(INT64_MAX) + 1u
                  ? INT64_MIN
                  : -static_cast<std::int64_t>(magnitude);
    } else {
      value = static_cast<std::int64_t>(magnitude);
    }
    (void)start;
    return Result<JsonValue>::success(JsonValue::integer(value));
  }

  std::string_view text_;
  std::size_t index_{0};
  std::size_t elements_{0};
};

void dump_value(const JsonValue& value, bool canonical, std::string& out) {
  switch (value.type()) {
    case JsonValue::Type::Null:
      out += "null";
      break;
    case JsonValue::Type::Bool:
      out += value.as_bool() ? "true" : "false";
      break;
    case JsonValue::Type::Int:
      out += std::to_string(value.as_int());
      break;
    case JsonValue::Type::String:
      out += json_escape(value.as_string());
      break;
    case JsonValue::Type::Array: {
      out.push_back('[');
      bool first = true;
      for (const auto& item : value.array_items()) {
        if (!first) out.push_back(',');
        first = false;
        dump_value(item, canonical, out);
      }
      out.push_back(']');
      break;
    }
    case JsonValue::Type::Object: {
      const JsonValue::Object* fields = &value.object_items();
      JsonValue::Object sorted;
      if (canonical) {
        sorted = *fields;
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        fields = &sorted;
      }
      out.push_back('{');
      bool first = true;
      for (const auto& field : *fields) {
        if (!first) out.push_back(',');
        first = false;
        out += json_escape(field.first);
        out.push_back(':');
        dump_value(field.second, canonical, out);
      }
      out.push_back('}');
      break;
    }
  }
}

}  // namespace

// ---------------------------------------------------------------------------------------
// Digest / hashing
// ---------------------------------------------------------------------------------------

bool Digest::is_zero() const noexcept {
  for (std::uint8_t byte : bytes) {
    if (byte != 0) return false;
  }
  return true;
}

std::string Digest::to_hex() const { return hex_encode(bytes.data(), bytes.size()); }

Result<Digest> Digest::from_hex(std::string_view text) {
  auto decoded = hex_decode(text, 32);
  if (!decoded) return Result<Digest>::failure(decoded.error);
  if (decoded->size() != 32) {
    return Result<Digest>::failure(ErrorCode::MalformedInput, "digest must be 32 bytes of hex",
                                   escape_preview(text));
  }
  Digest out;
  std::copy(decoded->begin(), decoded->end(), out.bytes.begin());
  return Result<Digest>::success(out);
}

Sha256::Sha256() : bit_length_(0), buffer_length_(0), finalized_(false) {
  state_[0] = 0x6a09e667u;
  state_[1] = 0xbb67ae85u;
  state_[2] = 0x3c6ef372u;
  state_[3] = 0xa54ff53au;
  state_[4] = 0x510e527fu;
  state_[5] = 0x9b05688cu;
  state_[6] = 0x1f83d9abu;
  state_[7] = 0x5be0cd19u;
  std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::transform(const std::uint8_t* block) noexcept {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];
  for (int i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const void* data, std::size_t length) noexcept {
  if (finalized_ || length == 0) return;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  bit_length_ += static_cast<std::uint64_t>(length) * 8u;
  std::size_t offset = 0;
  if (buffer_length_ != 0) {
    while (offset < length && buffer_length_ < 64) {
      buffer_[buffer_length_++] = bytes[offset++];
    }
    if (buffer_length_ == 64) {
      transform(buffer_);
      buffer_length_ = 0;
    }
  }
  while (length - offset >= 64) {
    transform(bytes + offset);
    offset += 64;
  }
  while (offset < length) {
    buffer_[buffer_length_++] = bytes[offset++];
  }
}

void Sha256::update(std::string_view text) noexcept { update(text.data(), text.size()); }

Digest Sha256::finish() noexcept {
  if (!finalized_) {
    finalized_ = true;
    const std::uint64_t bit_length = bit_length_;
    buffer_[buffer_length_++] = 0x80;
    if (buffer_length_ > 56) {
      while (buffer_length_ < 64) buffer_[buffer_length_++] = 0x00;
      transform(buffer_);
      buffer_length_ = 0;
    }
    while (buffer_length_ < 56) buffer_[buffer_length_++] = 0x00;
    for (int i = 0; i < 8; ++i) {
      buffer_[buffer_length_++] = static_cast<std::uint8_t>((bit_length >> (56 - i * 8)) & 0xFF);
    }
    transform(buffer_);
    buffer_length_ = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      const std::size_t base = i * 4;
      result_.bytes[base] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFF);
      result_.bytes[base + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFF);
      result_.bytes[base + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFF);
      result_.bytes[base + 3] = static_cast<std::uint8_t>(state_[i] & 0xFF);
    }
  }
  return result_;
}

Digest Sha256::hash(std::string_view text) noexcept {
  Sha256 hasher;
  hasher.update(text);
  return hasher.finish();
}

Digest Sha256::hash(const void* data, std::size_t length) noexcept {
  Sha256 hasher;
  hasher.update(data, length);
  return hasher.finish();
}

std::uint32_t crc32c(const void* data, std::size_t length, std::uint32_t seed) noexcept {
  const std::uint32_t* table = crc32c_table();
  std::uint32_t crc = ~seed;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  for (std::size_t i = 0; i < length; ++i) {
    crc = table[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8);
  }
  return ~crc;
}

std::string hex_encode(const void* data, std::size_t length) {
  static const char* kHex = "0123456789abcdef";
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::string out;
  out.reserve(length * 2);
  for (std::size_t i = 0; i < length; ++i) {
    out.push_back(kHex[(bytes[i] >> 4) & 0x0F]);
    out.push_back(kHex[bytes[i] & 0x0F]);
  }
  return out;
}

Result<std::vector<std::uint8_t>> hex_decode(std::string_view text, std::size_t max_bytes) {
  if (text.size() % 2 != 0) {
    return Result<std::vector<std::uint8_t>>::failure(ErrorCode::MalformedInput,
                                                      "hex input has an odd length", {});
  }
  const std::size_t byte_count = text.size() / 2;
  if (byte_count > max_bytes) {
    return Result<std::vector<std::uint8_t>>::failure(ErrorCode::TooLarge,
                                                      "hex input exceeds the allowed size",
                                                      std::to_string(byte_count));
  }
  std::vector<std::uint8_t> out;
  out.reserve(byte_count);
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < byte_count; ++i) {
    const int high = nibble(text[i * 2]);
    const int low = nibble(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return Result<std::vector<std::uint8_t>>::failure(ErrorCode::MalformedInput,
                                                        "hex input contains non-hex digits",
                                                        escape_preview(text, 32));
    }
    out.push_back(static_cast<std::uint8_t>((high << 4) | low));
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

// ---------------------------------------------------------------------------------------
// Canonical writer
// ---------------------------------------------------------------------------------------

CanonicalWriter& CanonicalWriter::tag(std::string_view name) {
  buffer_.push_back('T');
  u32(static_cast<std::uint32_t>(name.size()));
  buffer_.append(name);
  return *this;
}

CanonicalWriter& CanonicalWriter::u8(std::uint8_t value) {
  buffer_.push_back(static_cast<char>(value));
  return *this;
}

CanonicalWriter& CanonicalWriter::u32(std::uint32_t value) {
  for (int i = 0; i < 4; ++i) buffer_.push_back(static_cast<char>((value >> (i * 8)) & 0xFFu));
  return *this;
}

CanonicalWriter& CanonicalWriter::u64(std::uint64_t value) {
  for (int i = 0; i < 8; ++i) buffer_.push_back(static_cast<char>((value >> (i * 8)) & 0xFFu));
  return *this;
}

CanonicalWriter& CanonicalWriter::i64(std::int64_t value) {
  return u64(static_cast<std::uint64_t>(value));
}

CanonicalWriter& CanonicalWriter::boolean(bool value) { return u8(value ? 1u : 0u); }

CanonicalWriter& CanonicalWriter::str(std::string_view value) {
  u64(static_cast<std::uint64_t>(value.size()));
  buffer_.append(value);
  return *this;
}

CanonicalWriter& CanonicalWriter::raw(std::string_view bytes) {
  buffer_.append(bytes);
  return *this;
}

CanonicalWriter& CanonicalWriter::digest(const Digest& value) {
  buffer_.append(reinterpret_cast<const char*>(value.bytes.data()), value.bytes.size());
  return *this;
}

CanonicalWriter& CanonicalWriter::id(const Id128& value) {
  buffer_.append(reinterpret_cast<const char*>(value.bytes.data()), value.bytes.size());
  return *this;
}

Digest CanonicalWriter::digest() const { return Sha256::hash(buffer_); }

// ---------------------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------------------

JsonValue::JsonValue() : type_(Type::Null), bool_(false), int_(0) {}

JsonValue JsonValue::null() { return JsonValue(); }

JsonValue JsonValue::boolean(bool value) {
  JsonValue out;
  out.type_ = Type::Bool;
  out.bool_ = value;
  return out;
}

JsonValue JsonValue::integer(std::int64_t value) {
  JsonValue out;
  out.type_ = Type::Int;
  out.int_ = value;
  return out;
}

JsonValue JsonValue::text(std::string value) {
  JsonValue out;
  out.type_ = Type::String;
  out.string_ = std::move(value);
  return out;
}

JsonValue JsonValue::array(Array values) {
  JsonValue out;
  out.type_ = Type::Array;
  out.array_ = std::move(values);
  return out;
}

JsonValue JsonValue::object(Object fields) {
  JsonValue out;
  out.type_ = Type::Object;
  out.object_ = std::move(fields);
  return out;
}

JsonValue JsonValue::object(std::initializer_list<std::pair<std::string, JsonValue>> fields) {
  JsonValue out;
  out.type_ = Type::Object;
  out.object_.assign(fields.begin(), fields.end());
  return out;
}

std::size_t JsonValue::size() const noexcept {
  if (type_ == Type::Array) return array_.size();
  if (type_ == Type::Object) return object_.size();
  return 0;
}

bool JsonValue::empty() const noexcept { return size() == 0; }

const JsonValue* JsonValue::find(std::string_view key) const noexcept {
  if (type_ != Type::Object) return nullptr;
  for (const auto& field : object_) {
    if (field.first == key) return &field.second;
  }
  return nullptr;
}

bool JsonValue::contains(std::string_view key) const noexcept { return find(key) != nullptr; }

void JsonValue::set_field(std::string key, JsonValue value) {
  if (type_ != Type::Object) {
    type_ = Type::Object;
    object_.clear();
  }
  for (auto& field : object_) {
    if (field.first == key) {
      field.second = std::move(value);
      return;
    }
  }
  object_.emplace_back(std::move(key), std::move(value));
}

void JsonValue::push(JsonValue value) {
  if (type_ != Type::Array) {
    type_ = Type::Array;
    array_.clear();
  }
  array_.push_back(std::move(value));
}

std::size_t JsonValue::node_count() const noexcept {
  std::size_t total = 1;
  for (const auto& item : array_) total += item.node_count();
  for (const auto& field : object_) total += field.second.node_count();
  return total;
}

bool JsonValue::has_valid_shape(std::size_t max_depth) const noexcept {
  if (max_depth == 0) return false;
  if (array_.size() > limits::kMaxJsonElements) return false;
  if (object_.size() > limits::kMaxJsonElements) return false;
  if (string_.size() > limits::kMaxJsonStringBytes) return false;
  for (const auto& item : array_) {
    if (!item.has_valid_shape(max_depth - 1)) return false;
  }
  for (const auto& field : object_) {
    if (!field.second.has_valid_shape(max_depth - 1)) return false;
  }
  return true;
}

std::string JsonValue::dump(bool canonical) const {
  std::string out;
  dump_value(*this, canonical, out);
  return out;
}

Result<JsonValue> JsonValue::parse(std::string_view text) { return JsonParser(text).parse(); }

Result<bool> JsonValue::require_bool(std::string_view key) const {
  const JsonValue* field = find(key);
  if (field == nullptr) {
    return Result<bool>::failure(ErrorCode::MalformedInput, "required field is missing",
                                 escape_preview(key));
  }
  if (!field->is_bool()) {
    return Result<bool>::failure(ErrorCode::MalformedInput, "field is not a boolean",
                                 escape_preview(key));
  }
  return Result<bool>::success(field->as_bool());
}

Result<std::int64_t> JsonValue::require_int(std::string_view key) const {
  const JsonValue* field = find(key);
  if (field == nullptr) {
    return Result<std::int64_t>::failure(ErrorCode::MalformedInput, "required field is missing",
                                         escape_preview(key));
  }
  if (!field->is_int()) {
    return Result<std::int64_t>::failure(ErrorCode::MalformedInput, "field is not an integer",
                                         escape_preview(key));
  }
  return Result<std::int64_t>::success(field->as_int());
}

Result<std::string> JsonValue::require_string(std::string_view key) const {
  const JsonValue* field = find(key);
  if (field == nullptr) {
    return Result<std::string>::failure(ErrorCode::MalformedInput, "required field is missing",
                                        escape_preview(key));
  }
  if (!field->is_string()) {
    return Result<std::string>::failure(ErrorCode::MalformedInput, "field is not a string",
                                        escape_preview(key));
  }
  if (!is_valid_utf8(field->as_string())) {
    return Result<std::string>::failure(ErrorCode::MalformedInput, "field is not valid UTF-8",
                                        escape_preview(key));
  }
  return Result<std::string>::success(field->as_string());
}

Result<const JsonValue*> JsonValue::require_object(std::string_view key) const {
  const JsonValue* field = find(key);
  if (field == nullptr) {
    return Result<const JsonValue*>::failure(ErrorCode::MalformedInput, "required field is missing",
                                             escape_preview(key));
  }
  if (!field->is_object()) {
    return Result<const JsonValue*>::failure(ErrorCode::MalformedInput, "field is not an object",
                                             escape_preview(key));
  }
  return Result<const JsonValue*>::success(field);
}

Result<const JsonValue*> JsonValue::require_array(std::string_view key) const {
  const JsonValue* field = find(key);
  if (field == nullptr) {
    return Result<const JsonValue*>::failure(ErrorCode::MalformedInput, "required field is missing",
                                             escape_preview(key));
  }
  if (!field->is_array()) {
    return Result<const JsonValue*>::failure(ErrorCode::MalformedInput, "field is not an array",
                                             escape_preview(key));
  }
  return Result<const JsonValue*>::success(field);
}

Result<std::int64_t> JsonValue::require_int_in_range(std::string_view key, std::int64_t minimum,
                                                     std::int64_t maximum) const {
  auto value = require_int(key);
  if (!value) return value;
  if (*value < minimum || *value > maximum) {
    return Result<std::int64_t>::failure(ErrorCode::InvalidArgument, "field is out of range",
                                         escape_preview(key));
  }
  return value;
}

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2);
  out.push_back('"');
  for (char raw : text) {
    const auto c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          append_hex_escaped(out, c);
        } else {
          out.push_back(raw);
        }
        break;
    }
  }
  out.push_back('"');
  return out;
}

}  // namespace gpf
