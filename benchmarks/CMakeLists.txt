# Benchmarks. Built only when GPF_BUILD_BENCHMARKS is enabled.

add_executable(gpf_benchmarks main.cpp)
target_link_libraries(gpf_benchmarks PRIVATE gpf)
target_compile_features(gpf_benchmarks PRIVATE cxx_std_20)
if(MSVC)
  target_compile_options(gpf_benchmarks PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
else()
  target_compile_options(gpf_benchmarks PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
endif()
