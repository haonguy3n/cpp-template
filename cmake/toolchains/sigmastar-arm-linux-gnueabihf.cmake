# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/sigmastar-arm-linux-gnueabihf.cmake \
#         -DSE051_SIGMASTAR_TOOLCHAIN=/abs/path/to/gcc-11.1.0-...-arm-linux-gnueabihf \
#         -S . -B build/mk-arm32

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

if(NOT DEFINED SE051_SIGMASTAR_TOOLCHAIN)
  set(SE051_SIGMASTAR_TOOLCHAIN
      "/home/hao/work/26tpro/tools/gcc-11.1.0-20210608-sigmastar-glibc-x86_64_arm-linux-gnueabihf"
      CACHE PATH "SigmaStar GCC toolchain root")
endif()

set(_tc_bin     "${SE051_SIGMASTAR_TOOLCHAIN}/bin")
set(_tc_prefix  "${_tc_bin}/arm-linux-gnueabihf-")
set(_tc_sysroot "${SE051_SIGMASTAR_TOOLCHAIN}/arm-linux-gnueabihf/libc")

set(CMAKE_C_COMPILER   "${_tc_prefix}gcc")
set(CMAKE_CXX_COMPILER "${_tc_prefix}g++")
set(CMAKE_AR           "${_tc_prefix}ar")
set(CMAKE_RANLIB       "${_tc_prefix}ranlib")
set(CMAKE_STRIP        "${_tc_prefix}strip")

set(CMAKE_SYSROOT "${_tc_sysroot}")

set(_arch_flags "-march=armv7-a -mfpu=neon -mfloat-abi=hard")
set(CMAKE_C_FLAGS_INIT   "${_arch_flags}")
set(CMAKE_CXX_FLAGS_INIT "${_arch_flags}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
