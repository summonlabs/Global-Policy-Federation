# Package validation: installs the project into a throwaway prefix, builds the downstream consumer
# from a clean directory against that prefix only, and runs it.
#
# Run by CTest as:
#   cmake -DGPF_SOURCE_DIR=... -DGPF_BUILD_DIR=... -DGPF_WORK_DIR=... -P ValidatePackage.cmake
# Every step is executed for real; a failure stops the script with a non-zero exit code.

cmake_minimum_required(VERSION 3.20)

foreach(required GPF_SOURCE_DIR GPF_BUILD_DIR GPF_WORK_DIR)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "ValidatePackage.cmake requires -D${required}=...")
  endif()
endforeach()

set(prefix "${GPF_WORK_DIR}/prefix")
set(consumer_build "${GPF_WORK_DIR}/consumer-build")
file(REMOVE_RECURSE "${prefix}" "${consumer_build}")
file(MAKE_DIRECTORY "${GPF_WORK_DIR}")

message(STATUS "installing into ${prefix}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" --install "${GPF_BUILD_DIR}" --prefix "${prefix}"
  RESULT_VARIABLE install_result
  OUTPUT_VARIABLE install_output
  ERROR_VARIABLE install_error)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "install failed (${install_result}): ${install_output} ${install_error}")
endif()

# The installed package must be self-describing.
foreach(expected
    "include/gpf/policy.hpp"
    "include/gpf/effective.hpp"
    "include/gpf/store.hpp")
  if(NOT EXISTS "${prefix}/${expected}")
    message(FATAL_ERROR "installed package is missing ${expected}")
  endif()
endforeach()

file(GLOB config_files
     "${prefix}/lib/cmake/GlobalPolicyFederation/*.cmake"
     "${prefix}/lib64/cmake/GlobalPolicyFederation/*.cmake")
if(NOT config_files)
  message(FATAL_ERROR "installed package exports no CMake package configuration")
endif()

message(STATUS "configuring the downstream consumer against ${prefix}")
# The consumer must be built with the same toolchain as the library it links, so the toolchain of
# the validated build is passed through explicitly.
set(toolchain_arguments "")
if(DEFINED GPF_GENERATOR AND NOT GPF_GENERATOR STREQUAL "")
  list(APPEND toolchain_arguments -G "${GPF_GENERATOR}")
endif()
if(DEFINED GPF_CXX_COMPILER AND NOT GPF_CXX_COMPILER STREQUAL "")
  list(APPEND toolchain_arguments "-DCMAKE_CXX_COMPILER=${GPF_CXX_COMPILER}")
endif()
if(DEFINED GPF_CXX_COMPILER_ID AND GPF_CXX_COMPILER_ID STREQUAL "MSVC")
  list(APPEND toolchain_arguments -A x64)
endif()
execute_process(
  COMMAND "${CMAKE_COMMAND}"
          -S "${GPF_SOURCE_DIR}/examples/downstream-consumer"
          -B "${consumer_build}"
          -DCMAKE_BUILD_TYPE=Release
          ${toolchain_arguments}
          "-DCMAKE_PREFIX_PATH=${prefix}"
  RESULT_VARIABLE configure_result
  OUTPUT_VARIABLE configure_output
  ERROR_VARIABLE configure_error)
if(NOT configure_result EQUAL 0)
  message(FATAL_ERROR "consumer configure failed (${configure_result}): ${configure_output} ${configure_error}")
endif()

message(STATUS "building the downstream consumer")
execute_process(
  COMMAND "${CMAKE_COMMAND}" --build "${consumer_build}" --config Release
  RESULT_VARIABLE build_result
  OUTPUT_VARIABLE build_output
  ERROR_VARIABLE build_error)
if(NOT build_result EQUAL 0)
  message(FATAL_ERROR "consumer build failed (${build_result}): ${build_output} ${build_error}")
endif()

# Locate the produced binary without assuming a generator layout.
file(GLOB_RECURSE consumer_binaries "${consumer_build}/*gpf-downstream-consumer*")
set(consumer_binary "")
foreach(candidate ${consumer_binaries})
  if(NOT IS_DIRECTORY "${candidate}")
    get_filename_component(extension "${candidate}" EXT)
    if(extension STREQUAL ".exe" OR extension STREQUAL "")
      set(consumer_binary "${candidate}")
    endif()
  endif()
endforeach()
if(consumer_binary STREQUAL "")
  message(FATAL_ERROR "the consumer binary was not produced in ${consumer_build}")
endif()

message(STATUS "running ${consumer_binary}")
execute_process(COMMAND "${consumer_binary}" RESULT_VARIABLE run_result OUTPUT_VARIABLE run_output
                ERROR_VARIABLE run_error)
if(NOT run_result EQUAL 0)
  message(FATAL_ERROR "consumer run failed (${run_result}): ${run_output} ${run_error}")
endif()
string(FIND "${run_output}" "gpf-consumer-ok" marker)
if(marker EQUAL -1)
  message(FATAL_ERROR "consumer did not report success: ${run_output}")
endif()
message(STATUS "package validation passed: ${run_output}")
