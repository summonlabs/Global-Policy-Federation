#include "gpf/base.hpp"

#include <algorithm>
#include <cstdio>

namespace gpf {
namespace {

struct ErrorNameEntry {
  ErrorCode code;
  const char* name;
};

// Order mirrors the enum. Names are part of the machine-readable surface of this boundary.
constexpr ErrorNameEntry kErrorNames[] = {
    {ErrorCode::Ok, "ok"},
    {ErrorCode::InvalidArgument, "invalid-argument"},
    {ErrorCode::MalformedInput, "malformed-input"},
    {ErrorCode::TooLarge, "too-large"},
    {ErrorCode::Overflow, "overflow"},
    {ErrorCode::Underflow, "underflow"},
    {ErrorCode::NotFound, "not-found"},
    {ErrorCode::AlreadyExists, "already-exists"},
    {ErrorCode::DuplicateIdentity, "duplicate-identity"},
    {ErrorCode::Conflict, "conflict"},
    {ErrorCode::Unauthorized, "unauthorized"},
    {ErrorCode::Forbidden, "forbidden"},
    {ErrorCode::OverrideProhibited, "override-prohibited"},
    {ErrorCode::Unsupported, "unsupported"},
    {ErrorCode::UnknownCapability, "unknown-capability"},
    {ErrorCode::Incompatible, "incompatible"},
    {ErrorCode::VersionMismatch, "version-mismatch"},
    {ErrorCode::StaleGeneration, "stale-generation"},
    {ErrorCode::GenerationRegression, "generation-regression"},
    {ErrorCode::Revoked, "revoked"},
    {ErrorCode::Expired, "expired"},
    {ErrorCode::NotYetValid, "not-yet-valid"},
    {ErrorCode::Divergent, "divergent"},
    {ErrorCode::InteriorCorruption, "interior-corruption"},
    {ErrorCode::TornTail, "torn-tail"},
    {ErrorCode::IntegrityFailure, "integrity-failure"},
    {ErrorCode::UnsupportedFormat, "unsupported-format"},
    {ErrorCode::IoError, "io-error"},
    {ErrorCode::DiskFull, "disk-full"},
    {ErrorCode::PermissionDenied, "permission-denied"},
    {ErrorCode::Unavailable, "unavailable"},
    {ErrorCode::Cancelled, "cancelled"},
    {ErrorCode::Busy, "busy"},
    {ErrorCode::InvalidState, "invalid-state"},
    {ErrorCode::NotConnected, "not-connected"},
    {ErrorCode::Partitioned, "partitioned"},
    {ErrorCode::Reordered, "reordered"},
    {ErrorCode::Indeterminate, "indeterminate"},
    {ErrorCode::Refused, "refused"},
    {ErrorCode::Fenced, "fenced"},
    {ErrorCode::EpochFenced, "epoch-fenced"},
    {ErrorCode::LimitExceeded, "limit-exceeded"},
    {ErrorCode::Internal, "internal"},
};

constexpr std::size_t kErrorNameCount = sizeof(kErrorNames) / sizeof(kErrorNames[0]);

std::int64_t floor_div(std::int64_t numerator, std::int64_t denominator) noexcept {
  std::int64_t quotient = numerator / denominator;
  const std::int64_t remainder = numerator % denominator;
  if (remainder != 0 && ((remainder < 0) != (denominator < 0))) {
    --quotient;
  }
  return quotient;
}

bool parse_fixed_digits(std::string_view text, std::size_t offset, std::size_t count, int& out) {
  if (offset + count > text.size()) return false;
  int value = 0;
  for (std::size_t i = 0; i < count; ++i) {
    const char c = text[offset + i];
    if (c < '0' || c > '9') return false;
    value = value * 10 + (c - '0');
  }
  out = value;
  return true;
}

bool valid_day_of_month(int year, unsigned month, unsigned day) noexcept {
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  static const unsigned kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  unsigned limit = kDays[month - 1];
  if (month == 2) {
    const bool leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    if (leap) limit = 29;
  }
  return day <= limit;
}

}  // namespace

const char* error_code_name(ErrorCode code) noexcept {
  for (const auto& entry : kErrorNames) {
    if (entry.code == code) return entry.name;
  }
  return "unknown-error-code";
}

bool error_code_is_permanent(ErrorCode code) noexcept {
  switch (code) {
    // Conditions that may genuinely clear without the caller changing its request.
    case ErrorCode::Unavailable:
    case ErrorCode::Busy:
    case ErrorCode::NotConnected:
    case ErrorCode::Partitioned:
      return false;
    default:
      return true;
  }
}

std::string Error::to_string() const {
  std::string out = error_code_name(code);
  if (!message.empty()) {
    out += ": ";
    out += message;
  }
  if (!detail.empty()) {
    out += " [";
    out += detail;
    out += "]";
  }
  return out;
}

bool is_valid_utf8(std::string_view text) noexcept {
  std::size_t i = 0;
  const std::size_t n = text.size();
  while (i < n) {
    const auto byte = static_cast<unsigned char>(text[i]);
    std::size_t extra = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum = 0;
    if (byte < 0x80) {
      ++i;
      continue;
    } else if ((byte & 0xE0) == 0xC0) {
      extra = 1;
      code_point = byte & 0x1Fu;
      minimum = 0x80;
    } else if ((byte & 0xF0) == 0xE0) {
      extra = 2;
      code_point = byte & 0x0Fu;
      minimum = 0x800;
    } else if ((byte & 0xF8) == 0xF0) {
      extra = 3;
      code_point = byte & 0x07u;
      minimum = 0x10000;
    } else {
      return false;
    }
    if (extra > n - i - 1) return false;
    for (std::size_t k = 1; k <= extra; ++k) {
      const auto continuation = static_cast<unsigned char>(text[i + k]);
      if ((continuation & 0xC0) != 0x80) return false;
      code_point = (code_point << 6) | (continuation & 0x3Fu);
    }
    if (code_point < minimum) return false;                    // overlong encoding
    if (code_point > 0x10FFFF) return false;                   // outside Unicode
    if (code_point >= 0xD800 && code_point <= 0xDFFF) return false;  // surrogate half
    i += extra + 1;
  }
  return true;
}

std::string escape_preview(std::string_view text, std::size_t max_bytes) {
  std::string out;
  const std::size_t limit = std::min(text.size(), max_bytes);
  out.reserve(limit + 8);
  for (std::size_t i = 0; i < limit; ++i) {
    const auto c = static_cast<unsigned char>(text[i]);
    if (c >= 0x20 && c < 0x7F) {
      out.push_back(static_cast<char>(c));
    } else {
      char buffer[8];
      std::snprintf(buffer, sizeof(buffer), "\\x%02X", c);
      out += buffer;
    }
  }
  if (text.size() > limit) out += "...";
  return out;
}

bool is_valid_identifier(std::string_view text) noexcept {
  if (text.empty() || text.size() > limits::kMaxIdentifierLength) return false;
  const auto first = static_cast<unsigned char>(text.front());
  const bool first_ok = (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
                        (first >= '0' && first <= '9');
  if (!first_ok) return false;
  for (char raw : text) {
    const auto c = static_cast<unsigned char>(raw);
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '-' || c == ':' || c == '/';
    if (!ok) return false;
  }
  // Reject traversal-shaped identifiers even though they are otherwise well formed.
  if (text.find("..") != std::string_view::npos) return false;
  return true;
}

bool is_safe_filename_component(std::string_view text) noexcept {
  if (text.empty() || text.size() > 128) return false;
  if (text == "." || text == "..") return false;
  if (text.back() == '.' || text.back() == ' ') return false;
  for (char raw : text) {
    const auto c = static_cast<unsigned char>(raw);
    if (c < 0x20 || c == 0x7F) return false;
    switch (c) {
      case '<':
      case '>':
      case ':':
      case '"':
      case '/':
      case '\\':
      case '|':
      case '?':
      case '*':
        return false;
      default:
        break;
    }
  }
  // Windows device names are reserved in every directory and with any extension.
  static const char* kReserved[] = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3",
                                    "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                                    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
                                    "LPT7", "LPT8", "LPT9"};
  const std::string lowered = to_lower_ascii(text);
  const std::size_t dot = lowered.find('.');
  const std::string stem = dot == std::string::npos ? lowered : lowered.substr(0, dot);
  for (const char* reserved : kReserved) {
    if (stem == to_lower_ascii(reserved)) return false;
  }
  return true;
}

bool has_prefix(std::string_view text, std::string_view prefix) noexcept {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool has_suffix(std::string_view text, std::string_view suffix) noexcept {
  return text.size() >= suffix.size() &&
         text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string to_lower_ascii(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

std::string trim_ascii(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  while (begin < end) {
    const char c = text[begin];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      ++begin;
    } else {
      break;
    }
  }
  while (end > begin) {
    const char c = text[end - 1];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      --end;
    } else {
      break;
    }
  }
  return std::string(text.substr(begin, end - begin));
}

std::vector<std::string> split_ascii(std::string_view text, char delimiter) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (true) {
    const std::size_t position = text.find(delimiter, start);
    if (position == std::string_view::npos) {
      parts.emplace_back(text.substr(start));
      break;
    }
    parts.emplace_back(text.substr(start, position - start));
    start = position + 1;
  }
  return parts;
}

std::string join(const std::vector<std::string>& parts, std::string_view separator) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i != 0) out.append(separator);
    out.append(parts[i]);
  }
  return out;
}

bool Id128::is_nil() const noexcept {
  for (std::uint8_t byte : bytes) {
    if (byte != 0) return false;
  }
  return true;
}

std::string Id128::to_hex() const {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(32);
  for (std::uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4) & 0x0F]);
    out.push_back(kHex[byte & 0x0F]);
  }
  return out;
}

Result<Id128> Id128::from_hex(std::string_view text) {
  if (text.size() != 32) {
    return Result<Id128>::failure(ErrorCode::MalformedInput, "identifier is not 32 hex characters",
                                  escape_preview(text));
  }
  Id128 out;
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < 16; ++i) {
    const int high = nibble(text[i * 2]);
    const int low = nibble(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      return Result<Id128>::failure(ErrorCode::MalformedInput, "identifier contains non-hex digits",
                                    escape_preview(text));
    }
    out.bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return Result<Id128>::success(out);
}

IdGenerator::IdGenerator(std::uint64_t seed) : seed_(seed), rng_(seed) {}

Id128 IdGenerator::next() {
  while (true) {
    Id128 out;
    const std::uint64_t high = rng_();
    const std::uint64_t low = rng_();
    for (std::size_t i = 0; i < 8; ++i) {
      out.bytes[i] = static_cast<std::uint8_t>((high >> (i * 8)) & 0xFF);
      out.bytes[8 + i] = static_cast<std::uint8_t>((low >> (i * 8)) & 0xFF);
    }
    out.bytes[6] = static_cast<std::uint8_t>((out.bytes[6] & 0x0F) | 0x40);  // version 4
    out.bytes[8] = static_cast<std::uint8_t>((out.bytes[8] & 0x3F) | 0x80);  // RFC 4122 variant
    if (!out.is_nil()) return out;
  }
}

Result<Generation> Generation::next() const {
  if (value >= limits::kMaxGenerationValue) {
    return Result<Generation>::failure(ErrorCode::Overflow, "policy generation exhausted",
                                       "generation reached the reserved maximum");
  }
  return Result<Generation>::success(Generation{value + 1});
}

Result<SequenceNumber> SequenceNumber::next() const {
  if (value == UINT64_MAX) {
    return Result<SequenceNumber>::failure(ErrorCode::Overflow, "sequence number exhausted", {});
  }
  return Result<SequenceNumber>::success(SequenceNumber{value + 1});
}

Result<Epoch> Epoch::next() const {
  if (value == UINT64_MAX) {
    return Result<Epoch>::failure(ErrorCode::Overflow, "authority epoch exhausted", {});
  }
  return Result<Epoch>::success(Epoch{value + 1});
}

std::int64_t days_from_civil(int year, unsigned month, unsigned day) noexcept {
  const std::int64_t y = static_cast<std::int64_t>(year) - (month <= 2 ? 1 : 0);
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned mp = (month + 9u) % 12u;
  const unsigned doy = (153u * mp + 2u) / 5u + day - 1u;
  const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

void civil_from_days(std::int64_t days, int& year, unsigned& month, unsigned& day) noexcept {
  std::int64_t z = days + 719468;
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
  const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
  const unsigned mp = (5u * doy + 2u) / 153u;
  day = doy - (153u * mp + 2u) / 5u + 1u;
  month = mp < 10u ? mp + 3u : mp - 9u;
  year = static_cast<int>(y + (month <= 2u ? 1 : 0));
}

std::string Timestamp::to_iso8601() const {
  const std::int64_t days = floor_div(ms, 86400000);
  const std::int64_t millis_of_day = ms - days * 86400000;
  int year = 0;
  unsigned month = 0;
  unsigned day = 0;
  civil_from_days(days, year, month, day);
  const std::int64_t seconds_of_day = millis_of_day / 1000;
  const std::int64_t millis_part = millis_of_day % 1000;
  const int hour = static_cast<int>(seconds_of_day / 3600);
  const int minute = static_cast<int>((seconds_of_day % 3600) / 60);
  const int second = static_cast<int>(seconds_of_day % 60);
  char buffer[40];
  std::snprintf(buffer, sizeof(buffer), "%04d-%02u-%02uT%02d:%02d:%02d.%03dZ", year, month, day, hour,
                minute, second, static_cast<int>(millis_part));
  return std::string(buffer);
}

Result<Timestamp> Timestamp::parse_iso8601(std::string_view text) {
  // Accepted forms: YYYY-MM-DDTHH:MM:SSZ and YYYY-MM-DDTHH:MM:SS.mmmZ (UTC only).
  if (text.size() != 20 && text.size() != 24) {
    return Result<Timestamp>::failure(ErrorCode::MalformedInput, "timestamp length is invalid",
                                      escape_preview(text));
  }
  if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':' ||
      text.back() != 'Z') {
    return Result<Timestamp>::failure(ErrorCode::MalformedInput, "timestamp layout is invalid",
                                      escape_preview(text));
  }
  if (text.size() == 24 && text[19] != '.') {
    return Result<Timestamp>::failure(ErrorCode::MalformedInput, "timestamp needs .mmm before Z",
                                      escape_preview(text));
  }
  int year = 0;
  int month = 0;
  int day = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;
  int millis = 0;
  if (!parse_fixed_digits(text, 0, 4, year) || !parse_fixed_digits(text, 5, 2, month) ||
      !parse_fixed_digits(text, 8, 2, day) || !parse_fixed_digits(text, 11, 2, hour) ||
      !parse_fixed_digits(text, 14, 2, minute) || !parse_fixed_digits(text, 17, 2, second)) {
    return Result<Timestamp>::failure(ErrorCode::MalformedInput, "timestamp contains non-digits",
                                      escape_preview(text));
  }
  if (text.size() == 24 && !parse_fixed_digits(text, 20, 3, millis)) {
    return Result<Timestamp>::failure(ErrorCode::MalformedInput, "timestamp milliseconds invalid",
                                      escape_preview(text));
  }
  if (!valid_day_of_month(year, static_cast<unsigned>(month), static_cast<unsigned>(day))) {
    return Result<Timestamp>::failure(ErrorCode::MalformedInput, "timestamp calendar date invalid",
                                      escape_preview(text));
  }
  if (hour > 23 || minute > 59 || second > 59) {
    return Result<Timestamp>::failure(ErrorCode::MalformedInput, "timestamp time-of-day invalid",
                                      escape_preview(text));
  }
  const std::int64_t days = days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
  const std::int64_t total = days * 86400000 + static_cast<std::int64_t>(hour) * 3600000 +
                             static_cast<std::int64_t>(minute) * 60000 +
                             static_cast<std::int64_t>(second) * 1000 + millis;
  return Result<Timestamp>::success(Timestamp{total});
}

Result<Timestamp> Timestamp::plus_millis(Millis delta) const {
  auto sum = checked_add_i64(ms, delta);
  if (!sum) return Result<Timestamp>::failure(sum.error);
  return Result<Timestamp>::success(Timestamp{*sum});
}

}  // namespace gpf
