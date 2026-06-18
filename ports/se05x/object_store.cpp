#include <etlx/se/object_store.hpp>
#include <etlx/log/log.hpp>

extern "C" {
#include <fsl_sss_api.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
}

namespace etlx::se {

Result<ObjectStore::Uid> ObjectStore::GetUid() {
    ETLX_LOG_DEBUG("se: getUid");
    Uid uid{};
    size_t uid_len = uid.size();
    sss_status_t st =
        sss_session_prop_get_au8(conn_.session(), kSSS_SessionProp_UID, uid.data(), &uid_len);
    if (st != kStatus_SSS_Success) {
        ETLX_LOG_ERROR("se: uid failed (0x%04x) — SCP03 established?",
                       static_cast<unsigned>(st));
        return SeFail(kReadFailed, "sss_session_prop_get_au8(UID) failed");
    }
    ETLX_LOG_DEBUG("se: getUid OK (%zu bytes)", uid_len);
    return uid;
}

bool ObjectStore::Exists(uint32_t id) {
    KeyObject obj(conn_);
    bool found = obj.Open(id).has_value();
    ETLX_LOG_DEBUG("se: exists id=0x%08x -> %s", static_cast<unsigned>(id),
                   found ? "yes" : "no");
    return found;
}

Result<ObjectType> ObjectStore::GetType(uint32_t id) {
    KeyObject obj(conn_);
    if (auto st = obj.Open(id); !st)
        return SeFail(kReadFailed, "object not found");

    // get_handle (inside Open) fills cipherType from the SE object attributes.
    ObjectType type;
    switch (obj.raw()->cipherType) {
    case kSSS_CipherType_RSA:
    case kSSS_CipherType_RSA_CRT:
        type = ObjectType::Rsa;
        break;
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_EC_NIST_K:
    case kSSS_CipherType_EC_MONTGOMERY:
    case kSSS_CipherType_EC_TWISTED_ED:
    case kSSS_CipherType_EC_BRAINPOOL:
        type = ObjectType::Ecc;
        break;
    case kSSS_CipherType_AES:
    case kSSS_CipherType_DES:
    case kSSS_CipherType_HMAC:
    case kSSS_CipherType_CMAC:
        type = ObjectType::Symmetric;
        break;
    case kSSS_CipherType_Certificate:
        type = ObjectType::Certificate;
        break;
    case kSSS_CipherType_Binary:
        type = ObjectType::Binary;
        break;
    default:
        type = ObjectType::Other;
        break;
    }
    ETLX_LOG_DEBUG("se: type id=0x%08x cipherType=%u -> %d",
                   static_cast<unsigned>(id),
                   static_cast<unsigned>(obj.raw()->cipherType),
                   static_cast<int>(type));
    return type;
}

Status ObjectStore::Erase(uint32_t id) {
    ETLX_LOG_DEBUG("se: erase id=0x%08x", static_cast<unsigned>(id));
    KeyObject obj(conn_);
    auto st = obj.Open(id);
    if (!st)
        return st;
    if (sss_key_store_erase_key(conn_.keystore(), obj.raw()) != kStatus_SSS_Success)
        return SeFail(kWriteFailed, "sss_key_store_erase_key failed");
    ETLX_LOG_DEBUG("se: erase id=0x%08x OK", static_cast<unsigned>(id));
    return Ok();
}

Status ObjectStore::StoreBinary(uint32_t id, const uint8_t *data, size_t data_len,
                                 const char *tag) {
    KeyObject obj(conn_);
    auto st = obj.Allocate(id, kSSS_KeyPart_Default, kSSS_CipherType_Binary, data_len);
    if (!st)
        return st;

    sss_status_t sst = sss_key_store_set_key(conn_.keystore(), obj.raw(), data, data_len,
                                              data_len * 8, nullptr, 0);
    if (sst != kStatus_SSS_Success) {
        ETLX_LOG_ERROR("se: %s: sss_key_store_set_key failed (0x%04x)", tag,
                       static_cast<unsigned>(sst));
        return SeFail(kWriteFailed, "sss_key_store_set_key failed");
    }
    return Ok();
}

Status ObjectStore::WriteCert(uint32_t id, const uint8_t *der, size_t der_len) {
    ETLX_LOG_DEBUG("se: writeCert id=0x%08x len=%zu", static_cast<unsigned>(id), der_len);
    if (Exists(id)) {
        ETLX_LOG_DEBUG("se: writeCert: erasing existing 0x%08x", static_cast<unsigned>(id));
        auto st = Erase(id);
        if (!st) return st;
    }
    return StoreBinary(id, der, der_len, "writeCert");
}

Result<bool> ObjectStore::WriteBinary(uint32_t id, const uint8_t *data, size_t data_len,
                                       bool force) {
    ETLX_LOG_DEBUG("se: writeBinary id=0x%08x len=%zu force=%d",
                   static_cast<unsigned>(id), data_len, force);
    if (Exists(id)) {
        if (!force) {
            ETLX_LOG_INFO("se: writeBinary: 0x%08x exists (use force to overwrite)",
                          static_cast<unsigned>(id));
            return false;
        }
        auto st = Erase(id);
        if (!st) return Unexpected<>{st.error()};
    }
    auto st = StoreBinary(id, data, data_len, "writeBinary");
    if (!st) return Unexpected<>{st.error()};
    return true;
}

Result<ObjectStore::BlobData> ObjectStore::ReadBinary(uint32_t id) {
    ETLX_LOG_DEBUG("se: readBinary id=0x%08x", static_cast<unsigned>(id));
    KeyObject obj(conn_);
    if (auto st = obj.Open(id); !st)
        return SeFail(kReadFailed, "readBinary: object not found");

    BlobData buf;
    buf.resize(ETLX_SE_BLOB_CAPACITY);
    size_t len = buf.size();
    size_t bit_len = len * 8;
    sss_status_t st =
        sss_key_store_get_key(conn_.keystore(), obj.raw(), buf.data(), &len, &bit_len);
    if (st != kStatus_SSS_Success)
        return SeFail(kReadFailed, "sss_key_store_get_key(binary) failed");
    buf.resize(len);
    return buf;
}

Result<bool> ObjectStore::VerifyBinding(uint32_t key_id, const uint8_t *cert_der,
                                         size_t cert_len) {
    // 1. Generate 32 random bytes via the SE TRNG.
    uint8_t nonce[32];
    {
        sss_rng_context_t rng{};
        if (sss_rng_context_init(&rng, conn_.session()) != kStatus_SSS_Success)
            return SeFail(kRngFailed, "rng_context_init (verifyBinding)");
        sss_status_t st = sss_rng_get_random(&rng, nonce, sizeof(nonce));
        sss_rng_context_free(&rng);
        if (st != kStatus_SSS_Success)
            return SeFail(kRngFailed, "rng_get_random (verifyBinding)");
    }

    // 2. SHA-256 the nonce.
    uint8_t digest[32];
    if (mbedtls_sha256(nonce, sizeof(nonce), digest, 0) != 0)
        return SeFail(kKeyFailed, "sha256 (verifyBinding) failed");

    // 3. Sign with the SE key.
    auto key_res = RsaKey::Open(conn_, key_id);
    if (!key_res) return Unexpected<>{key_res.error()};
    auto sig_res = key_res.value().Sign(digest, sizeof(digest));
    if (!sig_res) return Unexpected<>{sig_res.error()};
    const auto &sig = sig_res.value();

    // 4. Verify with the cert's public key via mbedTLS.
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int r = mbedtls_x509_crt_parse_der(&crt, cert_der, cert_len);
    if (r != 0) {
        mbedtls_x509_crt_free(&crt);
        return SeFail(kReadFailed, "mbedtls_x509_crt_parse_der failed");
    }
    r = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                          sig.data(), sig.size());
    mbedtls_x509_crt_free(&crt);

    ETLX_LOG_DEBUG("se: verifyBinding key=0x%08x result=%s",
                   static_cast<unsigned>(key_id), r == 0 ? "OK" : "FAIL");
    return (r == 0);
}

} // namespace etlx::se
