# In-tree example consumers. The same standalone project is added here, and it reuses the target
# this build already defines. The package validation builds it from the installed prefix instead.

if(GPF_BUILD_EXAMPLES)
  add_subdirectory(downstream-consumer)
endif()
