cmake_minimum_required(VERSION 3.20)

project(GlobalPolicyFederation
  VERSION 1.0.0
  DESCRIPTION "Policy federation semantics for the Data Center Control Plane: propagation, compatibility, delegation, conflict containment and local override of facility policy across federated data centers."
  HOMEPAGE_URL "https://github.com/summonlabs/Global-Policy-Federation"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(GPF_BUILD_TESTS "Build the Global Policy Federation test suites" ON)
option(GPF_BUILD_APPS "Build the Global Policy Federation executables" ON)
option(GPF_BUILD_BENCHMARKS "Build the Global Policy Federation benchmarks" OFF)
option(GPF_BUILD_EXAMPLES "Build the in-tree example consumers" ON)
option(GPF_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

set(GPF_LIBRARY_SOURCES
  src/base.cpp
  src/codec.cpp
  src/policy.cpp
  src/authority.cpp
  src/effective.cpp
  src/platform.cpp
  src/store.cpp
  src/net.cpp
  src/protocol.cpp
  src/runtime.cpp
  src/plan.cpp
)

add_library(gpf ${GPF_LIBRARY_SOURCES})
add_library(SummonLabs::gpf ALIAS gpf)

target_include_directories(gpf
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_compile_features(gpf PUBLIC cxx_std_20)

if(MSVC)
  target_compile_options(gpf PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
  if(GPF_WARNINGS_AS_ERRORS)
    target_compile_options(gpf PRIVATE /WX)
  endif()
else()
  target_compile_options(gpf PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
  if(GPF_WARNINGS_AS_ERRORS)
    target_compile_options(gpf PRIVATE -Werror)
  endif()
endif()

find_package(Threads REQUIRED)
target_link_libraries(gpf PRIVATE Threads::Threads)

if(WIN32)
  target_link_libraries(gpf PRIVATE ws2_32)
endif()

if(GPF_BUILD_APPS)
  add_subdirectory(apps)
endif()

if(GPF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(GPF_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

if(GPF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

install(TARGETS gpf
  EXPORT GlobalPolicyFederationTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/GlobalPolicyFederationConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GlobalPolicyFederationConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/GlobalPolicyFederationConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/GlobalPolicyFederation")

# A build-tree package, so the in-tree example consumes exactly what an installed consumer
# consumes. The authoritative validation still builds against an installed prefix.
export(EXPORT GlobalPolicyFederationTargets
  FILE "${CMAKE_CURRENT_BINARY_DIR}/GlobalPolicyFederationTargets.cmake"
  NAMESPACE SummonLabs::)

install(EXPORT GlobalPolicyFederationTargets
  FILE GlobalPolicyFederationTargets.cmake
  NAMESPACE SummonLabs::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/GlobalPolicyFederation")

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/GlobalPolicyFederationConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/GlobalPolicyFederationConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/GlobalPolicyFederation")
