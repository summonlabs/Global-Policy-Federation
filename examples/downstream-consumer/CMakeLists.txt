# Standalone downstream project. Built from a clean directory against an installed Global Policy
# Federation package, it finds the package with find_package and links the namespaced target.
# When it is added inside this repository instead, the already-defined target is reused; the
# install validation always takes the find_package path.
cmake_minimum_required(VERSION 3.20)

project(GpfDownstreamConsumer LANGUAGES CXX)

if(NOT TARGET SummonLabs::gpf)
  find_package(GlobalPolicyFederation CONFIG REQUIRED)
endif()

add_executable(gpf-downstream-consumer main.cpp)
target_compile_features(gpf-downstream-consumer PRIVATE cxx_std_20)

# The exported, namespaced target carries its own include directories and transitive
# dependencies; the consumer declares nothing but the link.
target_link_libraries(gpf-downstream-consumer PRIVATE SummonLabs::gpf)

if(MSVC)
  target_compile_options(gpf-downstream-consumer PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8)
else()
  target_compile_options(gpf-downstream-consumer PRIVATE -Wall -Wextra -Wpedantic)
endif()
