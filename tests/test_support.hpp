#pragma once
// Minimal first-party test framework for Global Policy Federation.
//
// Deliberately small: registration, assertions with expression text, deterministic seeding and
// a plain exit status. There are no timeouts, watchdogs or process-kill semantics anywhere in
// this project: a hanging test is a defect to diagnose, not a condition to mask.

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace gpf_test {

class Context {
 public:
  void check(bool condition, const std::string& expression, const char* file, int line) {
    ++checks_;
    if (condition) return;
    ++failures_;
    std::ostringstream message;
    message << "  CHECK failed: " << expression << "\n    at " << file << ":" << line;
    failures_messages_.push_back(message.str());
    std::cout << message.str() << "\n";
  }

  template <class A, class B>
  void check_eq(const A& actual, const B& expected, const std::string& expression, const char* file,
                int line) {
    ++checks_;
    if (actual == expected) return;
    ++failures_;
    std::ostringstream message;
    message << "  CHECK_EQ failed: " << expression << "\n    actual:   " << to_text(actual)
            << "\n    expected: " << to_text(expected) << "\n    at " << file << ":" << line;
    failures_messages_.push_back(message.str());
    std::cout << message.str() << "\n";
  }

  void note(const std::string& text) { std::cout << "  note: " << text << "\n"; }

  int failures() const { return failures_; }
  int checks() const { return checks_; }
  const std::vector<std::string>& failure_messages() const { return failures_messages_; }

 private:
  template <class T>
  static std::string to_text(const T& value) {
    if constexpr (std::is_enum_v<T>) {
      return std::string("enum(") + std::to_string(static_cast<long long>(value)) + ")";
    } else if constexpr (requires(std::ostream& stream, const T& item) { stream << item; }) {
      std::ostringstream out;
      out << value;
      return out.str();
    } else {
      return "<unprintable>";
    }
  }
  static std::string to_text(bool value) { return value ? "true" : "false"; }

  int failures_{0};
  int checks_{0};
  std::vector<std::string> failures_messages_;
};

using TestFunction = void (*)(Context&);

struct TestCase {
  std::string suite;
  std::string name;
  TestFunction function;
};

class Registry {
 public:
  static Registry& instance() {
    static Registry registry;
    return registry;
  }

  bool add(TestCase test_case) {
    tests_.push_back(std::move(test_case));
    return true;
  }

  const std::vector<TestCase>& tests() const { return tests_; }

 private:
  std::vector<TestCase> tests_;
};

struct Registrar {
  Registrar(const char* suite, const char* name, TestFunction function) {
    Registry::instance().add(TestCase{suite, name, function});
  }
};

// Deterministic pseudo-random source shared by randomized tests. The seed is printed by the
// runner so a failing case can be replayed exactly.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : seed_(seed), engine_(seed) {}
  std::uint64_t next() { return engine_(); }
  std::uint64_t below(std::uint64_t bound) { return bound == 0 ? 0 : engine_() % bound; }
  bool chance(unsigned numerator, unsigned denominator) {
    return below(denominator) < numerator;
  }
  std::uint64_t seed() const { return seed_; }

 private:
  std::uint64_t seed_;
  std::mt19937_64 engine_;
};

int run_all(int argc, char** argv);

// Positional arguments passed to the test executable (for example the path of a helper binary).
const std::vector<std::string>& positional_args();

}  // namespace gpf_test

#define GPF_TEST(suite_name, test_name)                                        \
  static void gpf_test_##suite_name##_##test_name(::gpf_test::Context& context); \
  static const ::gpf_test::Registrar gpf_registrar_##suite_name##_##test_name( \
      #suite_name, #test_name, &gpf_test_##suite_name##_##test_name);          \
  static void gpf_test_##suite_name##_##test_name(::gpf_test::Context& context)

// Variadic so that expressions containing braced initializer lists compare correctly.
#define CHECK(...) \
  context.check((__VA_ARGS__), #__VA_ARGS__, __FILE__, __LINE__)

// Exactly two arguments: parenthesize an argument that contains a top-level comma.
#define CHECK_EQ(actual, expected) \
  context.check_eq((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)

// Single evaluation: REQUIRE is used with operations that mutate state.
#define REQUIRE(...)                                                        \
  do {                                                                      \
    const bool gpf_require_result = static_cast<bool>(__VA_ARGS__);         \
    context.check(gpf_require_result, #__VA_ARGS__, __FILE__, __LINE__);    \
    if (!gpf_require_result) {                                              \
      std::cout << "  REQUIRE aborted the remainder of this test\n";        \
      return;                                                               \
    }                                                                       \
  } while (false)

#define NOTE(text) context.note((text))
