#include <se051/ec_key.hpp>
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

// ECDSA signing/verification and the CSR signatureAlgorithm are fixed to
// SHA-256 (matching RsaKey's 32-byte digest path); a SHA-256 digest is valid to
// sign on any NIST-P curve.
constexpr sss_algorithm_t kEcdsaAlg = kAlgorithm_SSS_ECDSA_SHA256;

Status ApplyPolicy(Connection &conn, KeyObject &obj, EcCurve curve, KeyPolicy policy) {
    const uint32_t bits = static_cast<uint32_t>(curve);
    if (policy == KeyPolicy::Full) {
        if (sss_key_store_generate_key(conn.keystore(), obj.raw(), bits, nullptr) !=
                kStatus_SSS_Success)
            return SeFail(kKeyFailed, "sss_key_store_generate_key failed");
        return Ok();
    }

    sss_policy_u asym{};
    asym.type = KPolicy_Asym_Key;
    asym.policy.asymmkey.can_Sign = 1;
    asym.policy.asymmkey.can_Gen = 1;

    sss_policy_u common{};
    common.type = KPolicy_Common;
    common.policy.common.can_Read = 1;
    common.policy.common.req_Sm = 1;

    sss_policy_t pol{};
    pol.policies[0] = &asym;
    pol.policies[1] = &common;
    pol.nPolicies = 2;

    if (sss_key_store_generate_key(conn.keystore(), obj.raw(), bits, &pol) !=
            kStatus_SSS_Success)
        return SeFail(kKeyFailed, "sss_key_store_generate_key (policy) failed");
    return Ok();
}

} // namespace

Result<EcKey> EcKey::Generate(Connection &conn, uint32_t key_id, EcCurve curve,
                              KeyPolicy policy) {
    EcKey k(conn);
    k.curve_ = curve;
    const size_t bytes = static_cast<size_t>(curve) / 8;

    auto st = k.obj_.Allocate(key_id, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, bytes);
    if (!st)
        return SeFail(kKeyFailed, "key_object_allocate_handle failed");

    auto gen_st = ApplyPolicy(conn, k.obj_, curve, policy);
    if (!gen_st)
        return Unexpected<>{gen_st.error()};

    SE051_LOG_INFO("se: generated EC P-%u key id=0x%08x",
                  static_cast<unsigned>(curve), static_cast<unsigned>(key_id));
    return k;
}

Result<EcKey> EcKey::Open(Connection &conn, uint32_t key_id) {
    EcKey k(conn);
    auto st = k.obj_.Open(key_id);
    if (!st)
        return Unexpected<>{st.error()};

    // Recover the curve from the stored public key bit length.
    uint8_t spki_buf[SE051_SE_SPKI_CAPACITY];
    size_t spki_len = sizeof(spki_buf);
    size_t bits = 0;
    if (sss_key_store_get_key(conn.keystore(), k.obj_.raw(), spki_buf, &spki_len, &bits) ==
            kStatus_SSS_Success) {
        if      (bits >= 521) k.curve_ = EcCurve::P521;
        else if (bits >= 384) k.curve_ = EcCurve::P384;
        else                  k.curve_ = EcCurve::P256;
    }

    SE051_LOG_DEBUG("se: opened EC P-%u key id=0x%08x",
                   static_cast<unsigned>(k.curve_), static_cast<unsigned>(key_id));
    return k;
}

Result<EcKey::SigBytes> EcKey::Sign(const uint8_t *digest, size_t digest_len) {
    SE051_LOG_DEBUG("se: sign ECDSA digest_len=%zu", digest_len);
    sss_asymmetric_t ctx{};
    if (sss_asymmetric_context_init(&ctx, obj_.conn().session(), obj_.raw(),
                                    kEcdsaAlg, kMode_SSS_Sign) != kStatus_SSS_Success)
        return SeFail(kSignFailed, "asymmetric_context_init(sign) failed");

    SigBytes sig;
    sig.resize(SE051_SE_SIG_CAPACITY);
    size_t sig_len = sig.size();
    sss_status_t st = sss_asymmetric_sign_digest(&ctx, const_cast<uint8_t *>(digest), digest_len,
                                                 sig.data(), &sig_len);
    sss_asymmetric_context_free(&ctx);

    if (st != kStatus_SSS_Success)
        return SeFail(kSignFailed, "asymmetric_sign_digest failed");

    sig.resize(sig_len);
    return sig;
}

Result<bool> EcKey::Verify(const uint8_t *digest, size_t digest_len,
                           const uint8_t *sig, size_t sig_len) {
    SE051_LOG_DEBUG("se: verify ECDSA sig_len=%zu", sig_len);
    sss_asymmetric_t ctx{};
    if (sss_asymmetric_context_init(&ctx, obj_.conn().session(), obj_.raw(),
                                    kEcdsaAlg, kMode_SSS_Verify) != kStatus_SSS_Success)
        return SeFail(kSignFailed, "asymmetric_context_init(verify) failed");

    sss_status_t st = sss_asymmetric_verify_digest(
        &ctx, const_cast<uint8_t *>(digest), digest_len,
        const_cast<uint8_t *>(sig), sig_len);
    sss_asymmetric_context_free(&ctx);
    bool ok = (st == kStatus_SSS_Success);
    SE051_LOG_DEBUG("se: verify result=%s", ok ? "OK" : "FAIL");
    return ok;
}

Result<EcKey::SpkiDer> EcKey::PublicKeyDer() {
    SpkiDer buf;
    buf.resize(SE051_SE_SPKI_CAPACITY);
    size_t len = buf.size();
    size_t bits = 0;
    if (sss_key_store_get_key(obj_.conn().keystore(), obj_.raw(), buf.data(), &len, &bits) !=
            kStatus_SSS_Success)
        return SeFail(kKeyFailed, "sss_key_store_get_key(SPKI) failed");
    buf.resize(len);
    return buf;
}

Result<EcKey::CsrPem> EcKey::MakeCsr(const char *subject_dn) {
    auto spki_res = PublicKeyDer();
    if (!spki_res)
        return Unexpected<>{spki_res.error()};
    const SpkiDer &spki = spki_res.value();

    uint8_t cri_buf[SE051_SE_CSR_PEM_CAPACITY];
    int cri_len = detail::BuildCri(cri_buf, sizeof(cri_buf), subject_dn, spki.data(), spki.size());
    if (cri_len < 0)
        return SeFail(kKeyFailed, "buildCri failed");

    uint8_t digest[32];
    if (mbedtls_sha256(cri_buf + (sizeof(cri_buf) - static_cast<size_t>(cri_len)),
                       static_cast<size_t>(cri_len), digest, 0) != 0)
        return SeFail(kKeyFailed, "sha256 over CRI failed");

    auto sig_res = Sign(digest, sizeof(digest));
    if (!sig_res)
        return Unexpected<>{sig_res.error()};
    const SigBytes &sig = sig_res.value();

    // signatureAlgorithm: ecdsa-with-SHA256.
    CsrPem pem;
    pem.resize(SE051_SE_CSR_PEM_CAPACITY);
    const uint8_t *cri_start = cri_buf + sizeof(cri_buf) - static_cast<size_t>(cri_len);
    if (!detail::AssembleCsr(cri_start, static_cast<size_t>(cri_len),
                             sig.data(), sig.size(),
                             MBEDTLS_OID_ECDSA_SHA256, MBEDTLS_OID_SIZE(MBEDTLS_OID_ECDSA_SHA256),
                             pem.data(), pem.size()))
        return SeFail(kKeyFailed, "AssembleCsr/PEM failed");

    pem.resize(std::strlen(pem.data()));
    SE051_LOG_INFO("se: EC CSR generated (%zu bytes)", pem.size());
    return pem;
}

EcKey::EcKey(EcKey &&o) noexcept : obj_(std::move(o.obj_)), curve_(o.curve_) {}

EcKey::~EcKey() = default;

} // namespace se051
