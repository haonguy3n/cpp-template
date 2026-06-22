#include <se051/rsa_key.hpp>
#include <se051/log/log.hpp>
#include "csr_build.hpp"

#include <cstring>

extern "C" {
#include <fsl_sss_api.h>
#include <fsl_sss_se05x_policy.h>
#include "mbedtls/oid.h"
#include "mbedtls/sha256.h"
}

namespace se051 {

namespace {

Status ApplyPolicy(Connection &conn, KeyObject &obj, RsaBits bits, KeyPolicy policy) {
    if (policy == KeyPolicy::Full) {
        sss_status_t st =
            sss_key_store_generate_key(conn.keystore(), obj.raw(),
                                       static_cast<uint32_t>(bits), nullptr);
        if (st != kStatus_SSS_Success)
            return SeFail(kKeyFailed, "sss_key_store_generate_key failed");
        return Ok();
    }

    sss_policy_u asym{};
    asym.type = KPolicy_Asym_Key;
    asym.policy.asymmkey.can_Sign = 1;
    asym.policy.asymmkey.can_Decrypt = (policy == KeyPolicy::SignDecrypt) ? 1 : 0;
    asym.policy.asymmkey.can_Gen = 1;

    sss_policy_u common{};
    common.type = KPolicy_Common;
    common.policy.common.can_Read = 1;
    common.policy.common.can_Write = 0;
    common.policy.common.can_Delete = 0;
    common.policy.common.req_Sm = 1;

    sss_policy_t pol{};
    pol.policies[0] = &asym;
    pol.policies[1] = &common;
    pol.nPolicies = 2;

    sss_status_t st =
        sss_key_store_generate_key(conn.keystore(), obj.raw(),
                                   static_cast<uint32_t>(bits), &pol);
    if (st != kStatus_SSS_Success)
        return SeFail(kKeyFailed, "sss_key_store_generate_key (policy) failed");
    return Ok();
}

} // namespace

Result<RsaKey> RsaKey::Generate(Connection &conn, uint32_t key_id, RsaBits bits,
                                 KeyPolicy policy) {
    RsaKey k(conn);
    k.bits_ = static_cast<size_t>(bits);

    auto st = k.obj_.Allocate(key_id, kSSS_KeyPart_Pair, kSSS_CipherType_RSA, k.bits_ / 8);
    if (!st)
        return SeFail(kKeyFailed, "key_object_allocate_handle failed");

    auto gen_st = ApplyPolicy(conn, k.obj_, bits, policy);
    if (!gen_st)
        return Unexpected<>{gen_st.error()};

    SE051_LOG_INFO("se: generated RSA-%zu key id=0x%08x", k.bits_,
                  static_cast<unsigned>(key_id));
    return k;
}

Result<RsaKey> RsaKey::Open(Connection &conn, uint32_t key_id) {
    RsaKey k(conn);
    auto st = k.obj_.Open(key_id);
    if (!st)
        return Unexpected<>{st.error()};

    // Auto-detect modulus size from stored public key (needed for Sign buffer sizing
    // and for the opaque-pk key_len callback).
    uint8_t spki_buf[512];
    size_t spki_len = sizeof(spki_buf);
    size_t bits = 0;
    if (sss_key_store_get_key(conn.keystore(), k.obj_.raw(), spki_buf, &spki_len, &bits) ==
            kStatus_SSS_Success && bits > 0)
        k.bits_ = bits;

    SE051_LOG_DEBUG("se: opened RSA-%zu key id=0x%08x", k.bits_, static_cast<unsigned>(key_id));
    return k;
}

Result<RsaKey::SigBytes> RsaKey::Sign(const uint8_t *digest, size_t digest_len) {
    SE051_LOG_DEBUG("se: sign RSA-%zu digest_len=%zu", bits_, digest_len);
    sss_asymmetric_t ctx{};
    sss_status_t st = sss_asymmetric_context_init(&ctx, obj_.conn().session(), obj_.raw(),
                                                  kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                                  kMode_SSS_Sign);
    if (st != kStatus_SSS_Success)
        return SeFail(kSignFailed, "asymmetric_context_init(sign) failed");

    SigBytes sig;
    sig.resize(bits_ / 8);
    size_t sig_len = sig.size();
    st = sss_asymmetric_sign_digest(&ctx, const_cast<uint8_t *>(digest), digest_len,
                                    sig.data(), &sig_len);
    sss_asymmetric_context_free(&ctx);

    if (st != kStatus_SSS_Success)
        return SeFail(kSignFailed, "asymmetric_sign_digest failed");

    sig.resize(sig_len);
    return sig;
}

Result<bool> RsaKey::Verify(const uint8_t *digest, size_t digest_len,
                            const uint8_t *sig, size_t sig_len) {
    SE051_LOG_DEBUG("se: verify RSA-%zu sig_len=%zu", bits_, sig_len);
    sss_asymmetric_t ctx{};
    if (sss_asymmetric_context_init(&ctx, obj_.conn().session(), obj_.raw(),
                                    kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                    kMode_SSS_Verify) != kStatus_SSS_Success)
        return SeFail(kSignFailed, "asymmetric_context_init(verify) failed");

    sss_status_t st = sss_asymmetric_verify_digest(
        &ctx, const_cast<uint8_t *>(digest), digest_len,
        const_cast<uint8_t *>(sig), sig_len);
    sss_asymmetric_context_free(&ctx);
    bool ok = (st == kStatus_SSS_Success);
    SE051_LOG_DEBUG("se: verify result=%s", ok ? "OK" : "FAIL");
    return ok;
}

Result<RsaKey::SpkiDer> RsaKey::PublicKeyDer() {
    SE051_LOG_DEBUG("se: publicKeyDer RSA-%zu", bits_);
    SpkiDer buf;
    buf.resize(SE051_SE_SPKI_CAPACITY);
    size_t len = buf.size();
    size_t bits = 0;
    sss_status_t st =
        sss_key_store_get_key(obj_.conn().keystore(), obj_.raw(), buf.data(), &len, &bits);
    if (st != kStatus_SSS_Success)
        return SeFail(kKeyFailed, "sss_key_store_get_key(SPKI) failed");
    buf.resize(len);
    return buf;
}

Result<RsaKey::CsrPem> RsaKey::MakeCsr(const char *subject_dn) {
    auto spki_res = PublicKeyDer();
    if (!spki_res)
        return Unexpected<>{spki_res.error()};
    const SpkiDer &spki = spki_res.value();

    // Build CRI into a stack buffer.
    uint8_t cri_buf[SE051_SE_CSR_PEM_CAPACITY];
    int cri_len = detail::BuildCri(cri_buf, sizeof(cri_buf), subject_dn, spki.data(), spki.size());
    if (cri_len < 0)
        return SeFail(kKeyFailed, "buildCri failed");

    // SHA-256 the CRI.
    uint8_t digest[32];
    if (mbedtls_sha256(cri_buf + (sizeof(cri_buf) - static_cast<size_t>(cri_len)),
                       static_cast<size_t>(cri_len), digest, 0) != 0)
        return SeFail(kKeyFailed, "sha256 over CRI failed");

    // Sign the digest with the SE key.
    auto sig_res = Sign(digest, sizeof(digest));
    if (!sig_res)
        return Unexpected<>{sig_res.error()};
    const SigBytes &sig = sig_res.value();

    // Assemble and PEM-encode (signatureAlgorithm: sha256WithRSAEncryption).
    CsrPem pem;
    pem.resize(SE051_SE_CSR_PEM_CAPACITY);
    const uint8_t *cri_start =
        cri_buf + sizeof(cri_buf) - static_cast<size_t>(cri_len);
    if (!detail::AssembleCsr(cri_start, static_cast<size_t>(cri_len),
                             sig.data(), sig.size(),
                             MBEDTLS_OID_PKCS1_SHA256, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS1_SHA256),
                             pem.data(), pem.size()))
        return SeFail(kKeyFailed, "AssembleCsr/PEM failed");

    pem.resize(std::strlen(pem.data()));
    SE051_LOG_INFO("se: CSR generated (%zu bytes)", pem.size());
    return pem;
}

RsaKey::RsaKey(RsaKey &&o) noexcept : obj_(std::move(o.obj_)), bits_(o.bits_) {}

RsaKey::~RsaKey() = default;

} // namespace se051
