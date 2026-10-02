#pragma once
// Global Policy Federation (GPF) — foundational value types, identities, errors, limits.
//
// This header defines only portable, allocation-light value types with no I/O and no
// platform dependencies. Everything above it builds on these primitives.

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gpf {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;
inline constexpr const char* kProductName = "Global Policy Federation";
inline constexpr const char* kBoundaryName = "policy-federation";

// ---------------------------------------------------------------------------------------
// Limits. Every externally influenced size is bounded before allocation or use.
// ---------------------------------------------------------------------------------------
namespace limits {

inline constexpr std::size_t kMaxIdentifierLength = 96;
inline constexpr std::size_t kMaxShortTextLength = 512;
inline constexpr std::size_t kMaxTextLength = 4096;
inline constexpr std::size_t kMaxRationaleLength = 1024;
inline constexpr std::size_t kMaxRulesPerBundle = 4096;
inline constexpr std::size_t kMaxRulesPerCompilation = 20000;
inline constexpr std::size_t kMaxBundlesPerFederation = 8192;
inline constexpr std::size_t kMaxProvenanceEntries = 64;
inline constexpr std::size_t kMaxCapabilityRequirementsPerRule = 32;
inline constexpr std::size_t kMaxOverridesPerSite = 4096;
inline constexpr std::size_t kMaxReceiptsPerSite = 65536;
inline constexpr std::size_t kMaxConflictRecords = 65536;
inline constexpr std::size_t kMaxSitesPerFederation = 4096;
inline constexpr std::size_t kMaxGrantsPerFederation = 8192;
inline constexpr std::size_t kMaxRevocations = 65536;
inline constexpr std::size_t kMaxJsonDepth = 48;
inline constexpr std::size_t kMaxJsonElements = 262144;
inline constexpr std::size_t kMaxJsonStringBytes = 1048576;
inline constexpr std::size_t kMaxJsonDocumentBytes = 8u * 1024u * 1024u;
inline constexpr std::size_t kMaxWireMessageBytes = 8u * 1024u * 1024u;
inline constexpr std::size_t kMaxWorkerThreads = 32;
inline constexpr std::size_t kMaxQueueDepth = 4096;
inline constexpr std::size_t kMaxStoreRecordBytes = 8u * 1024u * 1024u;
inline constexpr std::uint64_t kMaxWalBytes = 256ull * 1024ull * 1024ull;
inline constexpr std::size_t kMaxPendingReceipts = 4096;
inline constexpr std::uint64_t kMaxGenerationValue = 0xFFFFFFFFFFFFFEFFull;
inline constexpr std::size_t kMaxOverrideExplanationEntries = 64;
inline constexpr std::size_t kMaxReconnectSyncRules = 8192;

}  // namespace limits

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

// Error codes carry the semantics this boundary refuses to collapse: unknown vs unsupported,
// stale vs revoked, incompatible vs unavailable, absent vs conflicted.
enum class ErrorCode : std::uint16_t {
  Ok = 0,
  InvalidArgument,
  MalformedInput,
  TooLarge,
  Overflow,
  Underflow,
  NotFound,
  AlreadyExists,
  DuplicateIdentity,
  Conflict,
  Unauthorized,
  Forbidden,
  OverrideProhibited,
  Unsupported,
  UnknownCapability,
  Incompatible,
  VersionMismatch,
  StaleGeneration,
  GenerationRegression,
  Revoked,
  Expired,
  NotYetValid,
  Divergent,
  InteriorCorruption,
  TornTail,
  IntegrityFailure,
  UnsupportedFormat,
  IoError,
  DiskFull,
  PermissionDenied,
  Unavailable,
  Cancelled,
  Busy,
  InvalidState,
  NotConnected,
  Partitioned,
  Reordered,
  Indeterminate,
  Refused,
  Fenced,
  EpochFenced,
  LimitExceeded,
  Internal,
};

// Stable machine-readable symbolic name. Never localized, never reordered.
const char* error_code_name(ErrorCode code) noexcept;

// True when the condition is a caller error that retrying identically cannot fix.
bool error_code_is_permanent(ErrorCode code) noexcept;

struct Error {
  ErrorCode code{ErrorCode::Ok};
  std::string message;
  std::string detail;

  Error() = default;
  Error(ErrorCode c, std::string m, std::string d = {})
      : code(c), message(std::move(m)), detail(std::move(d)) {}

  bool ok() const noexcept { return code == ErrorCode::Ok; }
  std::string to_string() const;
};

template <class T>
struct Result {
  std::optional<T> value;
  Error error;

  bool ok() const noexcept { return value.has_value(); }
  explicit operator bool() const noexcept { return ok(); }
  const T& operator*() const noexcept { return *value; }
  T& operator*() noexcept { return *value; }
  const T* operator->() const noexcept { return &*value; }
  T* operator->() noexcept { return &*value; }

  static Result success(T v) {
    Result r;
    r.value = std::move(v);
    return r;
  }
  static Result failure(ErrorCode code, std::string message, std::string detail = {}) {
    Result r;
    r.error = Error(code, std::move(message), std::move(detail));
    return r;
  }
  static Result failure(Error err) {
    Result r;
    r.error = std::move(err);
    return r;
  }
};

struct Status {
  Error error;

  Status() = default;
  explicit Status(Error e) : error(std::move(e)) {}

  bool ok() const noexcept { return error.ok(); }
  explicit operator bool() const noexcept { return ok(); }
  const Error& operator*() const noexcept { return error; }

  static Status success() { return Status(); }
  static Status failure(ErrorCode code, std::string message, std::string detail = {}) {
    return Status(Error(code, std::move(message), std::move(detail)));
  }
  static Status failure(Error err) { return Status(std::move(err)); }
};

// ---------------------------------------------------------------------------------------
// Checked arithmetic. Silent wraparound of capacities, generations, counts or sequence
// numbers is treated as a defect, not as arithmetic.
// ---------------------------------------------------------------------------------------

inline Result<std::uint64_t> checked_add_u64(std::uint64_t a, std::uint64_t b) {
  if (b > UINT64_MAX - a) {
    return Result<std::uint64_t>::failure(ErrorCode::Overflow, "unsigned addition overflow",
                                          "operands exceed 64-bit range");
  }
  return Result<std::uint64_t>::success(a + b);
}

inline Result<std::uint64_t> checked_sub_u64(std::uint64_t a, std::uint64_t b) {
  if (b > a) {
    return Result<std::uint64_t>::failure(ErrorCode::Underflow, "unsigned subtraction underflow",
                                          "subtrahend exceeds minuend");
  }
  return Result<std::uint64_t>::success(a - b);
}

inline Result<std::uint64_t> checked_mul_u64(std::uint64_t a, std::uint64_t b) {
  if (a != 0 && b > UINT64_MAX / a) {
    return Result<std::uint64_t>::failure(ErrorCode::Overflow, "unsigned multiplication overflow",
                                          "product exceeds 64-bit range");
  }
  return Result<std::uint64_t>::success(a * b);
}

inline Result<std::int64_t> checked_add_i64(std::int64_t a, std::int64_t b) {
  if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b)) {
    return Result<std::int64_t>::failure(ErrorCode::Overflow, "signed addition overflow",
                                         "operands exceed 64-bit range");
  }
  return Result<std::int64_t>::success(a + b);
}

inline Result<std::size_t> checked_size_add(std::size_t a, std::size_t b) {
  if (b > static_cast<std::size_t>(-1) - a) {
    return Result<std::size_t>::failure(ErrorCode::Overflow, "size addition overflow", {});
  }
  return Result<std::size_t>::success(a + b);
}

// ---------------------------------------------------------------------------------------
// Text validation helpers
// ---------------------------------------------------------------------------------------

// Strict UTF-8 validation (rejects overlong encodings, surrogates, values above U+10FFFF).
bool is_valid_utf8(std::string_view text) noexcept;

// Printable representation for diagnostics: non-printable bytes become escapes.
std::string escape_preview(std::string_view text, std::size_t max_bytes = 128);

bool is_valid_identifier(std::string_view text) noexcept;

// Windows reserved device names, trailing dot/space rules, "..", separators, control bytes.
bool is_safe_filename_component(std::string_view text) noexcept;

bool has_prefix(std::string_view text, std::string_view prefix) noexcept;
bool has_suffix(std::string_view text, std::string_view suffix) noexcept;
std::string to_lower_ascii(std::string_view text);
std::string trim_ascii(std::string_view text);
std::vector<std::string> split_ascii(std::string_view text, char delimiter);
std::string join(const std::vector<std::string>& parts, std::string_view separator);

// ---------------------------------------------------------------------------------------
// Identities. Every authoritative object has a stable identity that survives restarts,
// reconnects and reordering.
// ---------------------------------------------------------------------------------------

struct Id128 {
  std::array<std::uint8_t, 16> bytes{};

  static Id128 nil() noexcept { return Id128{}; }
  bool is_nil() const noexcept;
  std::string to_hex() const;
  static Result<Id128> from_hex(std::string_view text);

  friend bool operator==(const Id128& a, const Id128& b) noexcept { return a.bytes == b.bytes; }
  friend std::strong_ordering operator<=>(const Id128& a, const Id128& b) noexcept {
    return a.bytes <=> b.bytes;
  }
};

// Generates identities from a seedable, reproducible PRNG so that randomized tests can be
// replayed from a printed seed.
class IdGenerator {
 public:
  explicit IdGenerator(std::uint64_t seed);
  Id128 next();
  std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::uint64_t seed_;
  std::mt19937_64 rng_;
};

#define GPF_DECLARE_ID(TypeName, PrefixLiteral)                                          \
  struct TypeName {                                                                      \
    Id128 value{};                                                                       \
    static constexpr const char* type_name() noexcept { return #TypeName; }              \
    static constexpr const char* prefix() noexcept { return PrefixLiteral; }             \
    static constexpr std::size_t prefix_length() noexcept {                              \
      return sizeof(PrefixLiteral) - 1;                                                  \
    }                                                                                    \
    bool is_nil() const noexcept { return value.is_nil(); }                              \
    std::string to_string() const {                                                      \
      return std::string(PrefixLiteral) + value.to_hex();                                \
    }                                                                                    \
    static Result<TypeName> parse(std::string_view text) {                               \
      TypeName out;                                                                      \
      if (text.size() != prefix_length() + 32) {                                         \
        return Result<TypeName>::failure(ErrorCode::MalformedInput,                      \
                                         "identifier length is invalid",                 \
                                         std::string("expected ") + #TypeName);          \
      }                                                                                  \
      if (text.substr(0, prefix_length()) != std::string_view(PrefixLiteral)) {          \
        return Result<TypeName>::failure(ErrorCode::MalformedInput,                      \
                                         "identifier prefix is invalid",                 \
                                         escape_preview(text));                          \
      }                                                                                  \
      auto parsed = Id128::from_hex(text.substr(prefix_length()));                       \
      if (!parsed) return Result<TypeName>::failure(parsed.error);                       \
      out.value = *parsed;                                                               \
      return Result<TypeName>::success(out);                                             \
    }                                                                                    \
    friend bool operator==(const TypeName& a, const TypeName& b) noexcept {              \
      return a.value == b.value;                                                         \
    }                                                                                    \
    friend std::strong_ordering operator<=>(const TypeName& a, const TypeName& b) noexcept { \
      return a.value <=> b.value;                                                        \
    }                                                                                    \
  };

GPF_DECLARE_ID(PolicyBundleId, "pb-")
GPF_DECLARE_ID(RuleId, "rule-")
GPF_DECLARE_ID(FederationId, "fed-")
GPF_DECLARE_ID(MemberId, "mbr-")
GPF_DECLARE_ID(SiteId, "site-")
GPF_DECLARE_ID(GrantId, "grant-")
GPF_DECLARE_ID(RevocationId, "rvk-")
GPF_DECLARE_ID(ReceiptId, "rcpt-")
GPF_DECLARE_ID(OverrideId, "ovr-")
GPF_DECLARE_ID(ConflictId, "cfl-")
GPF_DECLARE_ID(StoreId, "store-")

#undef GPF_DECLARE_ID

// Monotonic counters. Generation identifies a revision of authoritative state; seq identifies
// writer order; epoch identifies an authority era that fences stale asynchronous work.
struct Generation {
  std::uint64_t value{0};

  bool is_nil() const noexcept { return value == 0; }
  Result<Generation> next() const;
  friend bool operator==(const Generation&, const Generation&) noexcept = default;
  friend std::strong_ordering operator<=>(const Generation&, const Generation&) noexcept = default;
};

struct SequenceNumber {
  std::uint64_t value{0};

  bool is_nil() const noexcept { return value == 0; }
  Result<SequenceNumber> next() const;
  friend bool operator==(const SequenceNumber&, const SequenceNumber&) noexcept = default;
  friend std::strong_ordering operator<=>(const SequenceNumber&, const SequenceNumber&) noexcept = default;
};

struct Epoch {
  std::uint64_t value{0};

  bool is_nil() const noexcept { return value == 0; }
  Result<Epoch> next() const;
  friend bool operator==(const Epoch&, const Epoch&) noexcept = default;
  friend std::strong_ordering operator<=>(const Epoch&, const Epoch&) noexcept = default;
};

// ---------------------------------------------------------------------------------------
// Time. Deterministic civil-calendar conversion; no locale, no time zone database.
// ---------------------------------------------------------------------------------------

using Millis = std::int64_t;

struct Timestamp {
  Millis ms{0};  // milliseconds since 1970-01-01T00:00:00Z, UTC

  static Timestamp from_unix_millis(Millis value) noexcept { return Timestamp{value}; }
  bool is_zero() const noexcept { return ms == 0; }
  std::string to_iso8601() const;
  static Result<Timestamp> parse_iso8601(std::string_view text);
  Result<Timestamp> plus_millis(Millis delta) const;
  friend bool operator==(const Timestamp&, const Timestamp&) noexcept = default;
  friend std::strong_ordering operator<=>(const Timestamp&, const Timestamp&) noexcept = default;
};

struct Duration {
  Millis ms{0};

  friend bool operator==(const Duration&, const Duration&) noexcept = default;
};

// Days <-> civil date helpers, exposed for deterministic tests.
std::int64_t days_from_civil(int year, unsigned month, unsigned day) noexcept;
void civil_from_days(std::int64_t days, int& year, unsigned& month, unsigned& day) noexcept;

}  // namespace gpf
