#include "test_support.hpp"

#include <cstring>
#include <string>

namespace gpf_test {

namespace {
std::vector<std::string> g_positional_args;
}

const std::vector<std::string>& positional_args() { return g_positional_args; }

int run_all(int argc, char** argv) {
  g_positional_args.clear();
  std::string suite_filter;
  std::string name_filter;
  bool list_only = false;
  std::uint64_t seed = 20260101ull;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--list") {
      list_only = true;
    } else if (argument.rfind("--suite=", 0) == 0) {
      suite_filter = argument.substr(8);
    } else if (argument.rfind("--test=", 0) == 0) {
      name_filter = argument.substr(7);
    } else if (argument.rfind("--seed=", 0) == 0) {
      seed = std::strtoull(argument.c_str() + 7, nullptr, 10);
    } else {
      g_positional_args.push_back(argument);
    }
  }

  const auto& tests = Registry::instance().tests();
  if (list_only) {
    for (const TestCase& test_case : tests) {
      std::cout << test_case.suite << "." << test_case.name << "\n";
    }
    return 0;
  }

  std::cout << "gpf test run: " << tests.size() << " registered tests, seed " << seed << "\n";
  int total_failures = 0;
  int executed = 0;
  int checks = 0;
  for (const TestCase& test_case : tests) {
    if (!suite_filter.empty() && test_case.suite != suite_filter) continue;
    if (!name_filter.empty() && test_case.name.rfind(name_filter, 0) != 0) continue;
    ++executed;
    std::cout.flush();
    Context context;
    std::cout << "[run ] " << test_case.suite << "." << test_case.name << "\n";
    test_case.function(context);
    checks += context.checks();
    if (context.failures() != 0) {
      total_failures += context.failures();
      std::cout << "[FAIL] " << test_case.suite << "." << test_case.name << " ("
                << context.failures() << " of " << context.checks() << " checks failed)\n";
    } else {
      std::cout << "[ ok ] " << test_case.suite << "." << test_case.name << " ("
                << context.checks() << " checks)\n";
    }
  }
  std::cout << "gpf test run complete: " << executed << " tests, " << checks << " checks, "
            << total_failures << " failures\n";
  return total_failures == 0 ? 0 : 1;
}

}  // namespace gpf_test
