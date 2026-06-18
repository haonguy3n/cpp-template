#pragma once
//
// etlx/se.hpp — single-header entry point for the SE05x secure-element support
// API. Include this one header to get the whole surface; link the CMake target
// `etlx::se05x` to pull in the implementation and its transitive dependencies
// (NXP plug-and-trust middleware, mbedTLS, ETL).
//
//   #include <etlx/se.hpp>
//   using namespace etlx::se;
//
// Importing into another CMake project (see docs/se_library.md for detail):
//
//   add_subdirectory(path/to/cpp-template etlx)   # or FetchContent
//   target_link_libraries(my_app PRIVATE etlx::se05x)
//
// Everything lives in namespace etlx::se. Results are reported through
// etlx::Result<T> / etlx::Status (no exceptions, no heap in the hot path).
//
// API surface re-exported here:
//   Connection   — RAII session to the SE (open/keystore-init/close).
//   ObjectStore  — UID, object existence/erase, cert + binary blob I/O,
//                  key⇄cert binding proof.
//   RsaKey       — generate/open an SE-resident RSA key; sign, verify,
//                  export SPKI, build a PKCS#10 CSR (private key never leaves
//                  the chip).
//   SeRandom     — etlx::crypto::Random backed by the SE hardware TRNG.
//   Scp03Admin   — Platform SCP03 static-key rotation (GP PUT KEY).
//   SetupOpaquePk— bridge an SE key into an mbedTLS pk context for mTLS.
//
// The default object IDs (kRsaKeyId / kRsaCertId / kDeviceInfoId) come from
// object_store.hpp and match the factory-provisioning layout used by se_factory.

#include <etlx/se/connection.hpp>   // Connection, SeError, SeFail
#include <etlx/se/key_object.hpp>   // KeyObject (low-level handle RAII)
#include <etlx/se/object_store.hpp> // ObjectStore + default object IDs
#include <etlx/se/random.hpp>       // SeRandom
#include <etlx/se/rsa_key.hpp>      // RsaKey, RsaBits, KeyPolicy
#include <etlx/se/scp03.hpp>        // Scp03Admin, Scp03KeySet, scp03_keyfile
#include <etlx/se/se_pk.hpp>        // SetupOpaquePk (mbedTLS bridge for mTLS)
