#pragma once

#include <etlx/etlx_config.hpp>
#include <etlx/se/key_object.hpp>
#include <etlx/se/rsa_key.hpp>

#include <etl/array.h>
#include <etl/vector.h>

namespace etlx::se {

// Default SE05x object IDs (matching the se051 project layout).
constexpr uint32_t kRsaKeyId     = 0xFE000001u;
constexpr uint32_t kRsaCertId    = 0xFE000002u;
constexpr uint32_t kDeviceInfoId = 0xFE000010u;

enum class ObjectType {
    Binary,      // raw binary blob
    Certificate, // X.509 certificate object
    Rsa,         // RSA key (RAW or CRT)
    Ecc,         // any EC curve family (NIST, Montgomery, Edwards, Brainpool)
    Symmetric,   // AES / DES / HMAC / CMAC
    Other,       // anything else the SE reports
};

// Object-store operations (cert/blob read-write) and management helpers.
// These use sss_key_store_set_key/get_key with kSSS_CipherType_Binary.
class ObjectStore {
public:
    using CertDer  = etl::vector<uint8_t, ETLX_SE_CERT_CAPACITY>;
    using BlobData = etl::vector<uint8_t, ETLX_SE_BLOB_CAPACITY>;
    using Uid      = etl::array<uint8_t, ETLX_SE_UID_LEN>;

    explicit ObjectStore(Connection &conn) : conn_(conn) {}

    // Read the 18-byte chip UID.
    Result<Uid> GetUid();

    // True if a persisted object with the given ID exists.
    bool Exists(uint32_t id);

    // Report what kind of object occupies a slot (binary / cert / RSA / ECC /
    // symmetric). Returns an error if the slot is empty.
    Result<ObjectType> GetType(uint32_t id);

    // Erase a persisted object. No-op if not present; returns error on failure.
    Status Erase(uint32_t id);

    // Write a DER certificate (erase-then-write if already present).
    Status WriteCert(uint32_t id, const uint8_t *der, size_t der_len);

    // Write a binary blob.  Returns false (no-op) if the object exists and
    // force is false; returns true if the write happened.
    Result<bool> WriteBinary(uint32_t id, const uint8_t *data, size_t data_len, bool force);

    // Read a binary object back.
    Result<BlobData> ReadBinary(uint32_t id);

    // Prove that the SE key at key_id matches the public key in a DER cert:
    // signs a random 32-byte nonce with the SE key, verifies the signature
    // against the cert's public key using mbedTLS.
    Result<bool> VerifyBinding(uint32_t key_id, const uint8_t *cert_der, size_t cert_len);

private:
    Status StoreBinary(uint32_t id, const uint8_t *data, size_t data_len, const char *tag);

    Connection &conn_;
};

} // namespace etlx::se
