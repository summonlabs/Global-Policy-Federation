#include "fixtures.hpp"
#include "test_support.hpp"

#include <limits>
#include <string>

using namespace gpf;
using namespace gpf_test;

namespace {

std::string repeat(char c, std::size_t count) { return std::string(count, c); }

}  // namespace

GPF_TEST(foundation, sha256_known_vectors) {
  CHECK_EQ(Sha256::hash("").to_hex(),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CHECK_EQ(Sha256::hash("abc").to_hex(),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK_EQ(
      Sha256::hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_hex(),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  CHECK_EQ(Sha256::hash(repeat('a', 1000000)).to_hex(),
           std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

GPF_TEST(foundation, sha256_incremental_matches_single_shot) {
  const std::string payload = repeat('x', 1000) + "boundary" + repeat('y', 55);
  Sha256 incremental;
  std::size_t offset = 0;
  const std::size_t chunks[] = {1, 7, 63, 64, 65, 100, 128};
  std::size_t index = 0;
  while (offset < payload.size()) {
    const std::size_t step = std::min(chunks[index % 7], payload.size() - offset);
    incremental.update(payload.data() + offset, step);
    offset += step;
    ++index;
  }
  CHECK_EQ(incremental.finish().to_hex(), Sha256::hash(payload).to_hex());
  // Finishing twice must return the same digest.
  CHECK_EQ(incremental.finish().to_hex(), Sha256::hash(payload).to_hex());
}

GPF_TEST(foundation, crc32c_known_vector) {
  const std::string text = "123456789";
  CHECK_EQ(crc32c(text.data(), text.size()), 0xE3069283u);
  CHECK_EQ(crc32c("", 0), 0u);
}

GPF_TEST(foundation, canonical_writer_is_deterministic_and_domain_separated) {
  CanonicalWriter first;
  first.tag("gpf.test.v1").u32(7).str("alpha").boolean(true);
  CanonicalWriter second;
  second.tag("gpf.test.v1").u32(7).str("alpha").boolean(true);
  CHECK(first.digest() == second.digest());
  CanonicalWriter other_tag;
  other_tag.tag("gpf.test.v2").u32(7).str("alpha").boolean(true);
  CHECK(!(other_tag.digest() == first.digest()));
  CanonicalWriter other_order;
  other_order.tag("gpf.test.v1").str("alpha").u32(7).boolean(true);
  CHECK(!(other_order.digest() == first.digest()));
}

GPF_TEST(foundation, hex_round_trip_and_rejection) {
  const std::string bytes = std::string("\x00\x01\xfe\xff", 4);
  const std::string encoded = hex_encode(bytes.data(), bytes.size());
  CHECK_EQ(encoded, std::string("0001feff"));
  auto decoded = hex_decode(encoded, 64);
  REQUIRE(decoded.ok());
  CHECK_EQ(decoded->size(), std::size_t{4});
  CHECK_EQ(std::string(reinterpret_cast<const char*>(decoded->data()), decoded->size()), bytes);
  CHECK(!hex_decode("abc", 64).ok());      // odd length
  CHECK(!hex_decode("zz", 64).ok());       // non-hex
  CHECK(!hex_decode("0011", 1).ok());      // over the caller's bound
  CHECK(!Digest::from_hex("00").ok());     // wrong size
}

GPF_TEST(foundation, json_round_trip_and_canonical_order) {
  auto parsed = JsonValue::parse(R"({"b":2,"a":[true,null,"x"],"c":{"d":-1}})");
  REQUIRE(parsed.ok());
  CHECK_EQ(parsed->dump(true), std::string(R"({"a":[true,null,"x"],"b":2,"c":{"d":-1}})"));
  auto reparsed = JsonValue::parse(parsed->dump(true));
  REQUIRE(reparsed.ok());
  CHECK_EQ(reparsed->dump(true), parsed->dump(true));
  auto value = JsonValue::parse(R"("A\u00e9\ud83d\ude00")");
  REQUIRE(value.ok());
  CHECK_EQ(value->as_string(), std::string("A\xC3\xA9\xF0\x9F\x98\x80"));
}

GPF_TEST(foundation, json_rejects_malformed_and_adversarial_input) {
  CHECK(!JsonValue::parse("").ok());
  CHECK(!JsonValue::parse("{").ok());
  CHECK(!JsonValue::parse("{\"a\":1,}").ok());
  CHECK(!JsonValue::parse("{\"a\":}").ok());
  CHECK(!JsonValue::parse("{a:1}").ok());
  CHECK(!JsonValue::parse("{\"a\":1,\"a\":2}").ok());   // duplicate key
  CHECK(!JsonValue::parse("[1,2").ok());
  CHECK(!JsonValue::parse("{} {}").ok());               // trailing content
  CHECK(!JsonValue::parse("{\"a\":1.5}").ok());         // non-integer number
  CHECK(!JsonValue::parse("{\"a\":1e5}").ok());
  CHECK(!JsonValue::parse("{\"a\":01}").ok());          // leading zero
  CHECK(!JsonValue::parse("{\"a\":9223372036854775808}").ok());   // int64 overflow
  CHECK(!JsonValue::parse("{\"a\":-9223372036854775809}").ok());
  CHECK(JsonValue::parse("{\"a\":-9223372036854775808}").ok());
  CHECK(JsonValue::parse("{\"a\":9223372036854775807}").ok());
  CHECK(!JsonValue::parse("\"\\ud800\"").ok());         // lone high surrogate
  CHECK(!JsonValue::parse("\"\\udc00\"").ok());         // lone low surrogate
  CHECK(!JsonValue::parse("\"\\q\"").ok());             // unknown escape
  CHECK(!JsonValue::parse("\"\\u00\"").ok());           // truncated escape
  CHECK(!JsonValue::parse(std::string("\"\x01\"")).ok());  // raw control byte
  CHECK(!JsonValue::parse(std::string("\"\xFF\"")).ok());  // invalid UTF-8
  CHECK(!JsonValue::parse(std::string("[\"\xC0\x80\"]")).ok());  // overlong encoding
}

GPF_TEST(foundation, json_enforces_depth_and_size_limits) {
  std::string deep;
  for (int i = 0; i < 200; ++i) deep += "[";
  for (int i = 0; i < 200; ++i) deep += "]";
  auto deep_result = JsonValue::parse(deep);
  CHECK(!deep_result.ok());
  CHECK_EQ(error_code_name(deep_result.error.code), std::string("limit-exceeded"));

  std::string wide = "[";
  for (std::size_t i = 0; i < limits::kMaxJsonElements + 10; ++i) {
    if (i != 0) wide += ",";
    wide += "1";
  }
  wide += "]";
  CHECK(!JsonValue::parse(wide).ok());

  std::string huge = "\"";
  huge += repeat('a', limits::kMaxJsonStringBytes + 1);
  huge += "\"";
  CHECK(!JsonValue::parse(huge).ok());
}

GPF_TEST(foundation, json_typed_accessors_report_field_errors) {
  auto value = JsonValue::parse(R"({"b":true,"i":3,"s":"text","o":{},"a":[]})");
  REQUIRE(value.ok());
  CHECK(value->require_bool("b").ok());
  CHECK(!value->require_bool("i").ok());
  CHECK(!value->require_bool("missing").ok());
  CHECK(!value->require_int("b").ok());
  CHECK_EQ(*value->require_int("i"), std::int64_t{3});
  CHECK(!value->require_int_in_range("i", 4, 9).ok());
  CHECK(value->require_int_in_range("i", 1, 9).ok());
  CHECK_EQ(*value->require_string("s"), std::string("text"));
  CHECK(value->require_object("o").ok());
  CHECK(!value->require_object("a").ok());
  CHECK(value->require_array("a").ok());
  CHECK(value->find("missing") == nullptr);
  CHECK(value->contains("s"));
}

GPF_TEST(foundation, utf8_validation_edge_cases) {
  CHECK(is_valid_utf8("plain ascii"));
  CHECK(is_valid_utf8("\xC3\xA9"));          // e acute
  CHECK(is_valid_utf8("\xE2\x82\xAC"));      // euro sign
  CHECK(is_valid_utf8("\xF0\x9F\x98\x80"));  // emoji
  CHECK(!is_valid_utf8("\xC0\x80"));          // overlong NUL
  CHECK(!is_valid_utf8("\xED\xA0\x80"));      // surrogate half
  CHECK(!is_valid_utf8("\xF4\x90\x80\x80"));  // above U+10FFFF
  CHECK(!is_valid_utf8("\xE2\x82"));          // truncated
  CHECK(!is_valid_utf8("\x80"));              // stray continuation
  CHECK(!is_valid_utf8("\xFF"));
}

GPF_TEST(foundation, identifier_and_filename_validation) {
  CHECK(is_valid_identifier("power/thermal"));
  CHECK(is_valid_identifier("cooling.loop-1"));
  CHECK(is_valid_identifier("9lives"));
  CHECK(!is_valid_identifier(""));
  CHECK(!is_valid_identifier("-leading"));
  CHECK(!is_valid_identifier("spaces here"));
  CHECK(!is_valid_identifier("../escape"));
  CHECK(!is_valid_identifier("a..b"));
  CHECK(!is_valid_identifier(repeat('a', limits::kMaxIdentifierLength + 1)));

  CHECK(is_safe_filename_component("wal-0000000001.log"));
  CHECK(is_safe_filename_component("snapshot.2.gpf"));
  CHECK(is_safe_filename_component("com0"));
  CHECK(!is_safe_filename_component(""));
  CHECK(!is_safe_filename_component("."));
  CHECK(!is_safe_filename_component(".."));
  CHECK(!is_safe_filename_component("CON"));
  CHECK(!is_safe_filename_component("con.txt"));
  CHECK(!is_safe_filename_component("AUX"));
  CHECK(!is_safe_filename_component("nul"));
  CHECK(!is_safe_filename_component("COM9.dat"));
  CHECK(!is_safe_filename_component("LPT1"));
  CHECK(!is_safe_filename_component("a/b"));
  CHECK(!is_safe_filename_component("a\\b"));
  CHECK(!is_safe_filename_component("name."));
  CHECK(!is_safe_filename_component("name "));
  CHECK(!is_safe_filename_component("a:b"));
  CHECK(!is_safe_filename_component("a?b"));
  CHECK(!is_safe_filename_component(std::string("a") + '\x7F' + "b"));
}

GPF_TEST(foundation, string_utilities) {
  CHECK_EQ(to_lower_ascii("MiXeD-Case"), std::string("mixed-case"));
  CHECK_EQ(trim_ascii("  \t padded \r\n"), std::string("padded"));
  const auto parts = split_ascii("a,b,,c", ',');
  CHECK_EQ(parts.size(), std::size_t{4});
  CHECK_EQ(parts[2], std::string(""));
  CHECK_EQ((join({"a", "b", "c"}, "-")), std::string("a-b-c"));
  CHECK(has_prefix("gpf.store", "gpf."));
  CHECK(has_suffix("gpf.store", ".store"));
  CHECK(!has_prefix("gpf", "gpf."));
  CHECK_EQ(escape_preview(std::string("a\x01") + "b", 16), std::string("a\\x01b"));
  CHECK_EQ(escape_preview("abcdef", 3), std::string("abc..."));
}

GPF_TEST(foundation, identity_encoding_and_generation) {
  IdGenerator ids(42);
  const Id128 first = ids.next();
  const Id128 second = ids.next();
  CHECK(!first.is_nil());
  CHECK(!(first == second));
  CHECK_EQ(first.to_hex().size(), std::size_t{32});
  auto parsed = Id128::from_hex(first.to_hex());
  REQUIRE(parsed.ok());
  CHECK(*parsed == first);
  CHECK(!Id128::from_hex("00").ok());
  CHECK(!Id128::from_hex(repeat('z', 32)).ok());
  CHECK(!Id128::from_hex(repeat('0', 31)).ok());

  // Determinism: the same seed reproduces the same identity stream.
  IdGenerator same_seed(42);
  CHECK(same_seed.next() == first);

  SiteId site;
  site.value = first;
  CHECK_EQ(site.to_string(), std::string("site-") + first.to_hex());
  CHECK(SiteId::parse(site.to_string()).ok());
  CHECK(!SiteId::parse("mbr-" + first.to_hex()).ok());
  CHECK(!MemberId::parse(site.to_string()).ok());

  Generation generation{limits::kMaxGenerationValue};
  CHECK(!generation.next().ok());
  CHECK(Generation{1}.next().ok());
  CHECK_EQ(Generation{1}.next()->value, std::uint64_t{2});
  CHECK(!SequenceNumber{UINT64_MAX}.next().ok());
  CHECK(!Epoch{UINT64_MAX}.next().ok());
}

GPF_TEST(foundation, timestamps_are_deterministic_and_validated) {
  CHECK_EQ(Timestamp{0}.to_iso8601(), std::string("1970-01-01T00:00:00.000Z"));
  CHECK_EQ(Timestamp{-1}.to_iso8601(), std::string("1969-12-31T23:59:59.999Z"));
  CHECK_EQ(Timestamp{1700000000123}.to_iso8601(), std::string("2023-11-14T22:13:20.123Z"));
  auto round_trip = Timestamp::parse_iso8601("2024-02-29T12:34:56.789Z");
  REQUIRE(round_trip.ok());
  CHECK_EQ(round_trip->to_iso8601(), std::string("2024-02-29T12:34:56.789Z"));
  auto no_millis = Timestamp::parse_iso8601("2024-02-29T12:34:56Z");
  REQUIRE(no_millis.ok());
  CHECK_EQ(no_millis->ms, round_trip->ms - 789);
  CHECK(!Timestamp::parse_iso8601("2023-02-29T00:00:00Z").ok());  // not a leap year
  CHECK(!Timestamp::parse_iso8601("2023-13-01T00:00:00Z").ok());
  CHECK(!Timestamp::parse_iso8601("2023-00-01T00:00:00Z").ok());
  CHECK(!Timestamp::parse_iso8601("2023-01-01T24:00:00Z").ok());
  CHECK(!Timestamp::parse_iso8601("2023-01-01T00:00:00").ok());   // missing Z
  CHECK(!Timestamp::parse_iso8601("2023-01-01 00:00:00Z").ok());  // space instead of T
  CHECK(!Timestamp::parse_iso8601("2023-01-01T00:00:00.12Z").ok());
  CHECK(!Timestamp::parse_iso8601("").ok());
  CHECK(!Timestamp{INT64_MAX}.plus_millis(1).ok());

  for (std::int64_t days = -40000; days <= 40000; days += 997) {
    int year = 0;
    unsigned month = 0;
    unsigned day = 0;
    civil_from_days(days, year, month, day);
    CHECK_EQ(days_from_civil(year, month, day), days);
  }
}

GPF_TEST(foundation, checked_arithmetic_refuses_wraparound) {
  CHECK(checked_add_u64(1, 2).ok());
  CHECK_EQ(*checked_add_u64(1, 2), std::uint64_t{3});
  CHECK(!checked_add_u64(UINT64_MAX, 1).ok());
  CHECK(!checked_sub_u64(0, 1).ok());
  CHECK(checked_sub_u64(5, 5).ok());
  CHECK(!checked_mul_u64(UINT64_MAX, 2).ok());
  CHECK(checked_mul_u64(0, UINT64_MAX).ok());
  CHECK(!checked_add_i64(INT64_MAX, 1).ok());
  CHECK(!checked_add_i64(INT64_MIN, -1).ok());
  CHECK(checked_add_i64(-5, 5).ok());
  CHECK(!checked_size_add(std::numeric_limits<std::size_t>::max(), 1).ok());
}