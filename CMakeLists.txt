cmake_minimum_required(VERSION 3.21)

project(etlx
  VERSION     0.1.0
  DESCRIPTION "Embedded C++ template library (ETL-based), Mender-style CLI + services"
  LANGUAGES   CXX
)

# Build options.
option(ETLX_BUILD_TESTS    "Build host unit tests (GoogleTest)" ON)
option(ETLX_BUILD_EXAMPLES "Build per-module example programs"  ON)
option(ETLX_BUILD_DEMOCLI  "Build the democli example app"      ON)
option(ETLX_NO_EXCEPTIONS  "Compile library/app code with -fno-exceptions -fno-rtti" ON)
option(ETLX_WITH_TLS       "Build the TLS/mTLS support (fetches mbedTLS from source)" ON)
option(ETLX_WITH_SE05X     "Build the NXP SE05x secure-element port (fetches plug-and-trust)" OFF)

if(ETLX_WITH_SE05X AND NOT ETLX_WITH_TLS)
  message(FATAL_ERROR "ETLX_WITH_SE05X requires ETLX_WITH_TLS (SE05x host-crypto uses mbedTLS)")
endif()
# The SE05x port compiles NXP's C middleware, so enable the C language for it.
if(ETLX_WITH_SE05X)
  enable_language(C)
endif()

# Exactly one TCP transport backend is compiled in, chosen here. 'posix' is the
# lean default; 'asio' fetches Boost and builds the Boost.Asio backend instead.
# The two are never linked together, so a binary only carries what it uses.
set(ETLX_TRANSPORT "posix" CACHE STRING "TCP transport backend: posix or asio")
set_property(CACHE ETLX_TRANSPORT PROPERTY STRINGS posix asio)
if(NOT ETLX_TRANSPORT MATCHES "^(posix|asio)$")
  message(FATAL_ERROR "ETLX_TRANSPORT must be 'posix' or 'asio' (got '${ETLX_TRANSPORT}')")
endif()

# Tests pull in GoogleTest which relies on exceptions/RTTI; when cross-compiling
# for aarch64 they still run under qemu, so keep them on by default everywhere.

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

# Dependencies (ETL, GoogleTest) via FetchContent.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(etlx_dependencies)

# Shared interface target carrying the compile flags and ETL config that every
# etlx translation unit needs.
add_library(etlx_flags INTERFACE)

target_compile_features(etlx_flags INTERFACE cxx_std_17)

# No-heap / no-exceptions design contract from the README. ETL_NO_EXCEPTIONS
# makes ETL report errors through its assert handler instead of throwing.
target_compile_definitions(etlx_flags INTERFACE ETL_NO_EXCEPTIONS)

target_compile_options(etlx_flags INTERFACE
  $<$<COMPILE_LANGUAGE:CXX>:-Wall>
  $<$<COMPILE_LANGUAGE:CXX>:-Wextra>
)

if(CMAKE_CROSSCOMPILING)
  message(STATUS "etlx: cross-compiling for ${CMAKE_SYSTEM_PROCESSOR} "
                 "(${CMAKE_CXX_COMPILER})")
else()
  message(STATUS "etlx: building for native host (${CMAKE_SYSTEM_PROCESSOR})")
endif()

# A second interface target carrying the strict embedded flags. Library/app
# code uses it; test code does not (GoogleTest needs exceptions/RTTI).
add_library(etlx_embedded_flags INTERFACE)
if(ETLX_NO_EXCEPTIONS)
  target_compile_options(etlx_embedded_flags INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
  )
endif()

# The library, ports, apps, examples and tests.
add_subdirectory(src)
add_subdirectory(ports/host)
if(ETLX_WITH_SE05X)
  add_subdirectory(ports/se05x)
endif()

# Select the single TCP transport. etlx::transport is the one consumers link;
# it pulls in exactly one backend and defines ETLX_TRANSPORT_ASIO so the
# etlx/net/tcp_socket.hpp alias resolves to the right class. Only the chosen
# backend (and its dependencies, e.g. Boost) is compiled.
message(STATUS "etlx: TCP transport = ${ETLX_TRANSPORT}")
if(ETLX_TRANSPORT STREQUAL "asio")
  add_subdirectory(ports/asio)
  add_library(etlx_transport INTERFACE)
  target_link_libraries(etlx_transport INTERFACE etlx::asio)
  target_include_directories(etlx_transport INTERFACE ${CMAKE_SOURCE_DIR}/ports)
  target_compile_definitions(etlx_transport INTERFACE ETLX_TRANSPORT_ASIO=1)
else()
  add_library(etlx_transport STATIC ports/host/host_tcp.cpp)
  target_link_libraries(etlx_transport PUBLIC etlx::host PRIVATE etlx_embedded_flags)
  target_include_directories(etlx_transport PUBLIC ${CMAKE_SOURCE_DIR}/ports)
endif()
add_library(etlx::transport ALIAS etlx_transport)

if(ETLX_BUILD_DEMOCLI)
  add_subdirectory(apps/democli)
endif()

if(ETLX_WITH_SE05X)
  add_subdirectory(apps/se_factory)
endif()

if(ETLX_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(ETLX_BUILD_TESTS)
  add_subdirectory(tests)
endif()
