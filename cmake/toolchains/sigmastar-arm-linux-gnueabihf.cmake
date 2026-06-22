# Cross-compilation toolchain for the SigmaStar SoC (26T Pro): 32-bit ARMv7
# hard-float, glibc. Uses the vendor GCC 11.1.0 toolchain shipped under
# 26tpro/tools. Mirrors SIGMASTAR_SCC_COPTS in dev-sentinel's build/build.sh.
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/sigmastar-arm-linux-gnueabihf.cmake \
#         -DETLX_SIGMASTAR_TOOLCHAIN=/abs/path/to/gcc-11.1.0-...-arm-linux-gnueabihf \
#         -S . -B build/mk-arm32

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Root of the unpacked vendor toolchain (override with -DETLX_SIGMASTAR_TOOLCHAIN=...).
if(NOT DEFINED ETLX_SIGMASTAR_TOOLCHAIN)
  set(ETLX_SIGMASTAR_TOOLCHAIN
      "/home/hao/work/26tpro/tools/gcc-11.1.0-20210608-sigmastar-glibc-x86_64_arm-linux-gnueabihf"
      CACHE PATH "SigmaStar GCC toolchain root")
endif()

set(_tc_bin     "${ETLX_SIGMASTAR_TOOLCHAIN}/bin")
set(_tc_prefix  "${_tc_bin}/arm-linux-gnueabihf-")
set(_tc_sysroot "${ETLX_SIGMASTAR_TOOLCHAIN}/arm-linux-gnueabihf/libc")

set(CMAKE_C_COMPILER   "${_tc_prefix}gcc")
set(CMAKE_CXX_COMPILER "${_tc_prefix}g++")
set(CMAKE_AR           "${_tc_prefix}ar")
set(CMAKE_RANLIB       "${_tc_prefix}ranlib")
set(CMAKE_STRIP        "${_tc_prefix}strip")

set(CMAKE_SYSROOT "${_tc_sysroot}")

# armv7-a + NEON hard-float — identical to SIGMASTAR_SCC_COPTS.
set(_arch_flags "-march=armv7-a -mfpu=neon -mfloat-abi=hard")
set(CMAKE_C_FLAGS_INIT   "${_arch_flags}")
set(CMAKE_CXX_FLAGS_INIT "${_arch_flags}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
