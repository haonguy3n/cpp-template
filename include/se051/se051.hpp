#pragma once
//
// se051/se051.hpp — single-header entry point for the SE05x secure-element support
// API. Include this one header to get the whole surface; link the CMake target
// `se051::se05x` to pull in the implementation and its transitive dependencies
// (NXP plug-and-trust middleware, mbedTLS, ETL).
//
//   #include <se051/se051.hpp>
//   using namespace se051;
//
// Importing into another CMake project (see docs/se_library.md for detail):
//
//   add_subdirectory(path/to/cpp-template se051)   # or FetchContent
//   target_link_libraries(my_app PRIVATE se051::se05x)
//
// Everything lives in namespace se051. Results are reported through
// se051::Result<T> / se051::Status (no exceptions, no heap in the hot path).
//
// API surface re-exported here:
//   Connection   — RAII session to the SE (open/keystore-init/close).
//   ObjectStore  — UID, object existence/erase, cert + binary blob I/O,
//                  key⇄cert binding proof.
//   RsaKey       — generate/open an SE-resident RSA key; sign, verify,
//                  export SPKI, build a PKCS#10 CSR (private key never leaves
//                  the chip).
//   EcKey        — same surface for NIST-P EC keys (ECDSA sign/verify, CSR).
//   SeRandom     — se051::crypto::Random backed by the SE hardware TRNG.
//   Scp03Admin   — Platform SCP03 static-key rotation (GP PUT KEY).
//   SetupOpaquePk— bridge an SE key into an mbedTLS pk context for mTLS.
//
// The default object IDs (kRsaKeyId / kRsaCertId / kDeviceInfoId) come from
// object_store.hpp and match the factory-provisioning layout used by se_factory.

#include <se051/connection.hpp>   // Connection, SeError, SeFail
#include <se051/key_object.hpp>   // KeyObject (low-level handle RAII)
#include <se051/object_store.hpp> // ObjectStore + default object IDs
#include <se051/random.hpp>       // SeRandom
#include <se051/rsa_key.hpp>      // RsaKey, RsaBits, KeyPolicy
#include <se051/ec_key.hpp>       // EcKey, EcCurve
#include <se051/scp03.hpp>        // Scp03Admin, Scp03KeySet, scp03_keyfile
#include <se051/se_pk.hpp>        // SetupOpaquePk (mbedTLS bridge for mTLS)
