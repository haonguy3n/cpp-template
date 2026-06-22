include(FetchContent)
FetchContent_Declare(
  mbedtls
  URL      https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.6/mbedtls-3.6.6.tar.bz2
  URL_HASH SHA256=8fb65fae8dcae5840f793c0a334860a411f884cc537ea290ce1c52bb64ca007a
)
set(ENABLE_PROGRAMS        OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING         OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
# Don't let mbedTLS add its own install() rules — its objects are bundled into
# libse051.a, so we don't want its headers/libs polluting the sysroot.
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mbedtls)

FetchContent_Declare(
  plugandtrust
  GIT_REPOSITORY https://github.com/NXP/plug-and-trust.git
  GIT_TAG        1ddf8cf0cdf9d7f77e32d7e62b19b6a58d74f5fa
  GIT_SHALLOW    FALSE
  SOURCE_SUBDIR  __no_top_level_build__
)
FetchContent_MakeAvailable(plugandtrust)
