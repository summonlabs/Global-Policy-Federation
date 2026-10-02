# Test executables. No TIMEOUT property is set anywhere: tests run to completion.

function(gpf_add_test target)
  add_executable(${target}
    ${target}.cpp
    test_main.cpp
    test_support.cpp)
  target_link_libraries(${target} PRIVATE gpf)
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_compile_features(${target} PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
  endif()
  # Extra arguments are positional inputs for the test, such as a helper binary path. The
  # generator expression resolves the artifact for single- and multi-configuration generators.
  add_test(NAME ${target} COMMAND $<TARGET_FILE:${target}> ${ARGN})
endfunction()

gpf_add_test(test_foundation)
gpf_add_test(test_policy)
gpf_add_test(test_authority)
gpf_add_test(test_effective)
gpf_add_test(test_protocol)
gpf_add_test(test_runtime)

# The durability suite drives a helper as a real, independent OS process.
add_executable(gpf_store_crash_helper store_crash_helper.cpp)
target_link_libraries(gpf_store_crash_helper PRIVATE gpf)
target_compile_features(gpf_store_crash_helper PRIVATE cxx_std_20)
if(MSVC)
  target_compile_options(gpf_store_crash_helper PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
else()
  target_compile_options(gpf_store_crash_helper PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()
gpf_add_test(test_store "$<TARGET_FILE:gpf_store_crash_helper>")

# Package validation: install into a throwaway prefix and build the downstream consumer against
# that prefix only, running the same commands a downstream user would run.
add_test(
  NAME package_validation
  COMMAND "${CMAKE_COMMAND}"
          "-DGPF_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
          "-DGPF_BUILD_DIR=${CMAKE_BINARY_DIR}"
          "-DGPF_WORK_DIR=${CMAKE_BINARY_DIR}/package-validation"
          "-DGPF_GENERATOR=${CMAKE_GENERATOR}"
          "-DGPF_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
          "-DGPF_CXX_COMPILER_ID=${CMAKE_CXX_COMPILER_ID}"
          "-DGPF_CONFIG=$<CONFIG>"
          -P "${CMAKE_SOURCE_DIR}/cmake/ValidatePackage.cmake")
# The end-to-end suite drives the built executables as real, independent OS processes.
gpf_add_test(test_multiprocess
  "$<TARGET_FILE:gpfctl>"
  "$<TARGET_FILE:gpf-federation>"
  "$<TARGET_FILE:gpf-site>")
