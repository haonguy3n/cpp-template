# se051: minimal C++ library over NXP Plug & Trust for the SE05x / SE051,
# real hardware only — T=1 over Linux I2C (/dev/i2c-*) with Platform SCP03.
#
# Builds a curated static library from NXP's Plug & Trust SSS sources compiled
# against our fetched mbedTLS 3.6.6, then a thin C++ facade on top.

set(SIMW_LIB_DIR ${plugandtrust_SOURCE_DIR})

# Match the hardware/middleware: SE051/SE052 applet, mbedTLS host crypto,
# Platform SCP03 authentication.
set(PTMW_Applet     SE05X_C    CACHE STRING "" FORCE)
set(PTMW_SE05X_Ver  07_02      CACHE STRING "" FORCE)
set(PTMW_HostCrypto MBEDTLS    CACHE STRING "" FORCE)
set(PTMW_SE05X_Auth PlatfSCP03 CACHE STRING "" FORCE)

# Select the mbedTLS 3.x API in the SSS sources (our mbedTLS is 3.6.6).
set(SSS_HAVE_MBEDTLS_2_X 0)

# Pulls in SIMW_SE_SOURCES / SIMW_SE_AUTH_SOURCES / SIMW_INC_DIR, the required
# ADD_DEFINITIONS (SSS_USE_FTR_FILE, T1oI2C, ...), and generates fsl_sss_ftr.h.
include(${SIMW_LIB_DIR}/simw_lib.cmake)

# simw_lib.cmake generates fsl_sss_ftr.h with SSS_HAVE_MBEDTLS_3_X=0 (the NXP
# build has no mbedTLS 3.x knowledge). We are on 3.6.6, so patch it to 1.
file(READ "${SIMW_LIB_DIR}/fsl_sss_ftr.h" _ftr)
string(REPLACE
  "#define SSS_HAVE_MBEDTLS_3_X 0"
  "#define SSS_HAVE_MBEDTLS_3_X 1"
  _ftr "${_ftr}")
file(WRITE "${SIMW_LIB_DIR}/fsl_sss_ftr.h" "${_ftr}")
unset(_ftr)

# Swap the OpenSSL host-crypto + keystore for the mbedTLS implementation.
list(REMOVE_ITEM SIMW_SE_SOURCES
  ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c
  ${SIMW_LIB_DIR}/sss/src/keystore/keystore_openssl.c)
list(APPEND SIMW_SE_SOURCES
  ${SIMW_LIB_DIR}/sss/src/mbedtls/fsl_sss_mbedtls_apis.c)

add_library(se051_simw STATIC ${SIMW_SE_SOURCES} ${SIMW_SE_AUTH_SOURCES})

target_include_directories(se051_simw SYSTEM PUBLIC ${SIMW_LIB_DIR} ${SIMW_INC_DIR})
target_link_libraries(se051_simw PUBLIC mbedtls mbedx509 mbedcrypto)

# Propagate transport/feature defines as PUBLIC so every consumer TU sees the
# same ex_sss_boot_ctx_t layout (the struct is preprocessor-configurable).
target_compile_definitions(se051_simw PUBLIC
  SSS_USE_FTR_FILE SMCOM_T1oI2C T1oI2C T1oI2C_UM11225)

# NXP's 3.x paths access mbedtls_ecp_keypair fields by their pre-3.x names;
# this is the documented mbedTLS escape hatch so MBEDTLS_PRIVATE(x) -> x.
target_compile_definitions(se051_simw PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS)

# NXP C sources are not warning-clean; don't fail our build on them.
target_compile_options(se051_simw PRIVATE -w)

# The C++ library: thin facade over the middleware + the logging runtime.
add_library(se051 STATIC
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
  log.cpp
)
add_library(se051::se051 ALIAS se051)
target_include_directories(se051 PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(se051 PUBLIC se051_flags se051_simw)

# --- Downstream consumption helpers -----------------------------------------
# CMake consumers just link `se051::se051`. For non-CMake consumers, merge the
# full link set into ONE static archive at a stable path, and install headers.
set(_se_combined "${CMAKE_CURRENT_BINARY_DIR}/libse051_combined.a")
set(_se_mri      "${CMAKE_CURRENT_BINARY_DIR}/se051_combined.mri")
file(GENERATE OUTPUT "${_se_mri}" CONTENT
"create ${_se_combined}
addlib $<TARGET_FILE:se051>
addlib $<TARGET_FILE:se051_simw>
addlib $<TARGET_FILE:mbedx509>
addlib $<TARGET_FILE:mbedcrypto>
save
end
")
add_custom_command(
  OUTPUT "${_se_combined}"
  COMMAND ${CMAKE_AR} -M < "${_se_mri}"
  DEPENDS se051 se051_simw mbedx509 mbedcrypto "${_se_mri}"
  COMMENT "Merging se051 + SSS + mbedTLS into one static archive"
  VERBATIM)
add_custom_target(se051_combined ALL DEPENDS "${_se_combined}")

# Install the self-contained archive + headers so a Yocto recipe stages them
# into the sysroot for downstream recipes to link/include:
#   ${libdir}/libse051.a       (se051 + SSS + mbedTLS, one file, -fPIC)
#   ${includedir}/se051/*.hpp
#   cmake --install <build> --component se051 --prefix /usr
# The `se051` component installs ONLY our archive + headers, not the bundled
# mbedTLS/everest/p256m install rules.
include(GNUInstallDirs)
install(FILES "${_se_combined}" DESTINATION ${CMAKE_INSTALL_LIBDIR} RENAME libse051.a
        COMPONENT se051)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/se051 DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        COMPONENT se051)
