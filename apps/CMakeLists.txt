# Command line applications. Each one exercises the boundary for real: no simulated transports
# and no fixtures compiled into the binaries.

function(gpf_add_app target)
  add_executable(${target} ${target}.cpp)
  target_link_libraries(${target} PRIVATE gpf)
  target_compile_features(${target} PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    if(GPF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    if(GPF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
  install(TARGETS ${target} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endfunction()

gpf_add_app(gpfctl)
gpf_add_app(gpf-federation)
gpf_add_app(gpf-site)
