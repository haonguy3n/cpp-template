cmake_minimum_required(VERSION 3.21)

project(se051
  VERSION     0.1.0
  DESCRIPTION "Minimal C++ library for the NXP SE05x / SE051 secure element"
  LANGUAGES   C CXX
)

option(SE051_BUILD_EXAMPLES "Build the quickstart example" ON)

# Real hardware only: the SE05x is reached over Linux I2C (/dev/i2c-*) with
# Platform SCP03 authentication (see src/se051/CMakeLists.txt).

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build everything position-independent so the static library (and the bundled
# mbedTLS / SSS objects) can be linked into a shared object or PIE. Set before
# FetchContent so the mbedTLS and Plug & Trust targets inherit it.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(se051_dependencies)

add_library(se051_flags INTERFACE)
target_compile_features(se051_flags INTERFACE cxx_std_17)
target_compile_options(se051_flags INTERFACE
  $<$<COMPILE_LANGUAGE:CXX>:-Wall>
  $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
)

if(CMAKE_CROSSCOMPILING)
  message(STATUS "se051: cross-compiling for ${CMAKE_SYSTEM_PROCESSOR} (${CMAKE_CXX_COMPILER})")
else()
  message(STATUS "se051: building for native host (${CMAKE_SYSTEM_PROCESSOR})")
endif()

add_subdirectory(src/se051)

if(SE051_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
