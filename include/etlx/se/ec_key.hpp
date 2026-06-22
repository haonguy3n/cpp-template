#pragma once

#include <etlx/etlx_config.hpp>
#include <etlx/se/key_object.hpp>
#include <etlx/se/rsa_key.hpp>  // for KeyPolicy (shared with RSA)

#include <etl/string.h>
#include <etl/vector.h>

extern "C" {
#include <fsl_sss_api.h>
}

namespace etlx::se {

// NIST-P curve selector for EC key generation. The value is the curve's bit
// length, which the SSS layer uses to pick the curve for kSSS_CipherType_EC_NIST_P.
enum class EcCurve : uint32_t {
    P256 = 256,
    P384 = 384,
    P521 = 521,
};

// Operations on a single EC (NIST-P) key pair stored in the SE05x. Move-only.
// Mirrors RsaKey. Signing/verification use ECDSA over a SHA-256 digest; the
// signature is DER-encoded (SEQUENCE of r,s). The destructor does NOT erase the
// SE-resident key object.
class EcKey {
public:
    using SpkiDer = etl::vector<uint8_t, ETLX_SE_SPKI_CAPACITY>;
    using SigBytes = etl::vector<uint8_t, ETLX_SE_SIG_CAPACITY>;
    using CsrPem = etl::string<ETLX_SE_CSR_PEM_CAPACITY>;

    // Generate a fresh EC key pair and persist it in the SE.
    static Result<EcKey> Generate(Connection &conn, uint32_t key_id, EcCurve curve,
                                  KeyPolicy policy = KeyPolicy::Full);

    // Bind to an existing persisted EC key.
    static Result<EcKey> Open(Connection &conn, uint32_t key_id);

    // Sign a SHA-256 digest with ECDSA. Returns the DER-encoded signature.
    Result<SigBytes> Sign(const uint8_t *digest, size_t digest_len);

    // Verify a DER ECDSA signature over a SHA-256 digest. Returns an error on a
    // hardware fault; returns false if the signature is simply invalid.
    Result<bool> Verify(const uint8_t *digest, size_t digest_len,
                        const uint8_t *sig, size_t sig_len);

    // Export the public key as DER SubjectPublicKeyInfo.
    Result<SpkiDer> PublicKeyDer();

    // Generate a PKCS#10 CSR (ecdsa-with-SHA256) signed by the SE key. The
    // private key never leaves the SE. subject_dn is an RFC 4514 DN string.
    Result<CsrPem> MakeCsr(const char *subject_dn);

    EcCurve curve() const { return curve_; }

    ~EcKey();
    EcKey(EcKey &&) noexcept;
    EcKey &operator=(EcKey &&) = delete;
    EcKey(const EcKey &) = delete;
    EcKey &operator=(const EcKey &) = delete;

private:
    explicit EcKey(Connection &conn) : obj_(conn), curve_(EcCurve::P256) {}

    KeyObject obj_;
    EcCurve curve_;
};

} // namespace etlx::se
