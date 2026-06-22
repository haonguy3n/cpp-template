# SE05x host port (Phases 0-1: build spike + session/RNG).
#
# Builds a curated static library from NXP's Plug & Trust SSS sources, compiled
# against etlx's fetched mbedTLS 3.6.6 (the 3.x API surface, SSS_HAVE_MBEDTLS_2_X
# = 0). This reuses the upstream simw_lib.cmake source/include lists and its
# fsl_sss_ftr.h generation, then swaps the OpenSSL keystore for the mbedTLS one,
# exactly as the standalone SE051 project does.
#
# Like ports/asio this is a hosted-OS port: it links a C middleware that uses
# the heap, so it is NOT compiled with the no-exceptions/no-heap core flags.

set(SIMW_LIB_DIR ${plugandtrust_SOURCE_DIR})

# Transport selection.
# i2c    (default): T1oI2C — direct Linux I2C bus (/dev/i2c-*), real hardware.
# socket: JRCP V1 over TCP — NXP's GenericJRCPServer simulator or VCOM bridge.
#         Set EX_SSS_BOOT_SSS_PORT=127.0.0.1:8050 (or your bridge address).
# sim:    T1oI2C with TCP I2C PAL — wolfSSL SE050 software simulator.
#         Build simulator: https://github.com/wolfSSL/simulators/tree/main/SE050Sim
#         Set EX_SSS_BOOT_SSS_PORT=127.0.0.1:8050 before running tests.
set(ETLX_SE05X_TRANSPORT "i2c" CACHE STRING "SE05x transport: i2c, socket, or sim")
set_property(CACHE ETLX_SE05X_TRANSPORT PROPERTY STRINGS i2c socket sim)
if(NOT ETLX_SE05X_TRANSPORT MATCHES "^(i2c|socket|sim)$")
  message(FATAL_ERROR "ETLX_SE05X_TRANSPORT must be 'i2c', 'socket', or 'sim'")
endif()
message(STATUS "etlx: SE05x transport = ${ETLX_SE05X_TRANSPORT}")

# Match the hardware/middleware (see CLAUDE.md in the SE051 project).
set(PTMW_Applet     SE05X_C   CACHE STRING "" FORCE)
set(PTMW_SE05X_Ver  07_02     CACHE STRING "" FORCE)  # 07_xx = SE051/SE052
set(PTMW_HostCrypto MBEDTLS   CACHE STRING "" FORCE)
# wolfSSL simulator does not implement SCP03 — use plain auth for sim transport.
if(ETLX_SE05X_TRANSPORT STREQUAL "sim")
  set(PTMW_SE05X_Auth None CACHE STRING "" FORCE)
else()
  set(PTMW_SE05X_Auth PlatfSCP03 CACHE STRING "" FORCE)
endif()

# Select the mbedTLS 3.x API in the SSS sources (our mbedTLS is 3.6.6).
set(SSS_HAVE_MBEDTLS_2_X 0)

# Pulls in SIMW_SE_SOURCES / SIMW_SE_AUTH_SOURCES / SIMW_INC_DIR, the required
# ADD_DEFINITIONS (SSS_USE_FTR_FILE, T1oI2C, ...), and generates fsl_sss_ftr.h.
include(${SIMW_LIB_DIR}/simw_lib.cmake)

# simw_lib.cmake generates fsl_sss_ftr.h with SSS_HAVE_MBEDTLS_3_X=0 because the
# NXP build system has no mbedTLS 3.x knowledge.  We are on 3.6.6, so patch the
# generated file to 1 immediately after generation.  The patch is idempotent
# (string(REPLACE) is a no-op when the old string is absent) and runs every
# configure, after simw_lib.cmake, so compilation always sees the correct value.
file(READ "${SIMW_LIB_DIR}/fsl_sss_ftr.h" _ftr)
string(REPLACE
  "#define SSS_HAVE_MBEDTLS_3_X 0"
  "#define SSS_HAVE_MBEDTLS_3_X 1"
  _ftr "${_ftr}")
file(WRITE "${SIMW_LIB_DIR}/fsl_sss_ftr.h" "${_ftr}")
unset(_ftr)

# Swap the OpenSSL host-crypto + keystore for the mbedTLS implementation (the
# mbedTLS keystore lives inside fsl_sss_mbedtls_apis.c).
list(REMOVE_ITEM SIMW_SE_SOURCES
  ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
  ${SIMW_LIB_DIR}/sss/src/keystore/keystore_openssl.c)
list(APPEND SIMW_SE_SOURCES
  ${SIMW_LIB_DIR}/sss/src/mbedtls/fsl_sss_mbedtls_apis.c)

# Transport swap: socket replaces T1oI2C sources with our JRCP V1 socket client.
if(ETLX_SE05X_TRANSPORT STREQUAL "socket")
  list(REMOVE_ITEM SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/smComT1oI2C.c)
  # Remove T1oI2C glob and hardware-reset driver (calls smComT1oI2C_ComReset).
  list(FILTER SIMW_SE_SOURCES EXCLUDE REGEX ".*/T1oI2C/.*")
  list(FILTER SIMW_SE_SOURCES EXCLUDE REGEX ".*/platform/rsp/se05x_reset\\.c$")
  list(APPEND SIMW_SE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/smComSocket_fd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/smComSocket.c)
  # Override the compile-time transport flags set by simw_lib.cmake.
  remove_definitions(-DSMCOM_T1oI2C -DT1oI2C -DT1oI2C_UM11225)
  add_definitions(-DSMCOM_JRCP_V1=1)
  # smComSocket.h lives in ports/se05x — add to include path.
  set(SIMW_INC_DIR "${SIMW_INC_DIR};${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Simulator transport: T1oI2C protocol stack, but I2C PAL replaced by a TCP
# socket that connects to the wolfSSL SE050 software simulator (tcp_server).
# EX_SSS_BOOT_SSS_PORT=127.0.0.1:8050 (parsed by i2c_sim.c).
# See: https://github.com/wolfSSL/simulators/tree/main/SE050Sim
if(ETLX_SE05X_TRANSPORT STREQUAL "sim")
  # Replace the real I2C PAL and GPIO reset with simulator stubs.
  list(REMOVE_ITEM SIMW_SE_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/linux/i2c_a7.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/rsp/se05x_reset.c)
  list(APPEND SIMW_SE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/i2c_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/se05x_reset_stub.c)
endif()

add_library(etlx_simw STATIC ${SIMW_SE_SOURCES} ${SIMW_SE_AUTH_SOURCES})

target_include_directories(etlx_simw SYSTEM PUBLIC
  ${SIMW_LIB_DIR}
  ${SIMW_INC_DIR}
)

# mbedTLS targets come from the fetched mbedtls (ETLX_WITH_TLS). SSS host-crypto
# uses mbedcrypto/x509; tls is harmless to include.
target_link_libraries(etlx_simw PUBLIC mbedtls mbedx509 mbedcrypto)

# Propagate the transport-selection defines and SSS_USE_FTR_FILE as PUBLIC so
# every consumer TU sees the same ex_sss_boot_ctx_t layout (ODR: the struct
# is configurable via preprocessor, so all TUs that include NXP headers must
# have identical defines or they will silently disagree on the struct size).
# add_definitions() inside simw_lib.cmake is directory-scoped and does NOT
# propagate to sibling directories (e.g. tests/), so we duplicate them here
# as target-level PUBLIC definitions.
if(ETLX_SE05X_TRANSPORT STREQUAL "socket")
  target_compile_definitions(etlx_simw PUBLIC SSS_USE_FTR_FILE SMCOM_JRCP_V1=1)
else()
  # i2c and sim both use the T1oI2C protocol stack.
  target_compile_definitions(etlx_simw PUBLIC
    SSS_USE_FTR_FILE SMCOM_T1oI2C T1oI2C T1oI2C_UM11225)
endif()

# MBEDTLS_ALLOW_PRIVATE_ACCESS: inside the 3.x code paths, NXP accesses
# mbedtls_ecp_keypair fields as ->grp / ->d / ->Q using the old names.  In
# mbedTLS 3.x those fields are declared as MBEDTLS_PRIVATE(grp) which normally
# expands to private_grp.  This flag makes MBEDTLS_PRIVATE(x) expand to just x
# (the documented mbedTLS escape hatch for legacy code), so the struct fields
# keep their pre-3.x names when NXP TUs parse the mbedTLS headers.
target_compile_definitions(etlx_simw PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)

# NXP C sources are not warning-clean; keep them from failing our build and
# don't impose our strict flags on third-party code.
target_compile_options(etlx_simw PRIVATE -w)

# etlx_se05x: the C++ façade over the NXP middleware.
# Phase 0: se05x_probe.cpp (build-spike TU, verifies SSS headers link)
# Phase 1: se_connection.cpp (Connection RAII), se_random.cpp (SeRandom)
# Phase 2: rsa_key.cpp (RSA generate/open/sign/CSR), object_store.cpp (cert/blob)
# Phase 3: scp03.cpp (GP PUT KEY rotation), scp03_keyfile.cpp (key file I/O)
add_library(etlx_se05x STATIC
  se05x_probe.cpp
  se_connection.cpp
  se_random.cpp
  rsa_key.cpp
  ec_key.cpp
  csr_build.cpp
  object_store.cpp
  scp03.cpp
  scp03_keyfile.cpp
  se_pk.cpp
)
add_library(etlx::se05x ALIAS etlx_se05x)
target_include_directories(etlx_se05x PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(etlx_se05x PUBLIC etlx::etlx etlx::host etlx_simw)

# --- Downstream consumption helpers -----------------------------------------
# A CMake consumer just links `etlx::se05x` and gets etlx_simw + etlx + host +
# mbedTLS transitively, in the right order. But non-CMake consumers (e.g.
# dev-sentinel's legacy Makefile.proj build of sentinel-service) link by path
# and would otherwise have to dig the six archives out of the FetchContent
# `_deps/` tree and wrap them in `-Wl,--start-group`. The combined archive +
# install rules below give them ONE static library at a stable path.

# Merge the full SE link set into a single self-contained archive using an `ar`
# MRI script (portable across the vendor cross-`ar`). Order inside the archive
# doesn't matter — `ar` resolves an archive's own members as a set.
set(_se_combined "${CMAKE_CURRENT_BINARY_DIR}/libetlx_se05x_combined.a")
set(_se_mri      "${CMAKE_CURRENT_BINARY_DIR}/etlx_se05x_combined.mri")
file(GENERATE OUTPUT "${_se_mri}" CONTENT
"create ${_se_combined}
addlib $<TARGET_FILE:etlx_se05x>
addlib $<TARGET_FILE:etlx_simw>
addlib $<TARGET_FILE:etlx>
addlib $<TARGET_FILE:etlx_host>
addlib $<TARGET_FILE:mbedx509>
addlib $<TARGET_FILE:mbedcrypto>
save
end
")
add_custom_command(
  OUTPUT "${_se_combined}"
  COMMAND ${CMAKE_AR} -M < "${_se_mri}"
  DEPENDS etlx_se05x etlx_simw etlx etlx_host mbedx509 mbedcrypto "${_se_mri}"
  COMMENT "Merging etlx SE05x + SSS + mbedTLS into one static archive"
  VERBATIM)
add_custom_target(etlx_se05x_combined ALL DEPENDS "${_se_combined}")

# `cmake --install <build> --prefix <staging>` stages the headers + the combined
# archive so the dev-sentinel module can reference stable paths:
#   <staging>/lib/libetlx_se05x_combined.a   and   <staging>/include/etlx/...
install(FILES "${_se_combined}" DESTINATION lib)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/etlx DESTINATION include)
