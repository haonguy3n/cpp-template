#pragma once

#include <se051/config.hpp>
#include <se051/key_object.hpp>

#include <string>
#include <vector>

extern "C" {
#include <fsl_sss_api.h>
}

namespace se051 {

// Key size selector for RSA generation.
enum class RsaBits : uint32_t {
    k2048 = 2048,
    k4096 = 4096,
};

// Key policy controlling which SE operations are permitted on the stored key.
enum class KeyPolicy {
    Full,        // sign + decrypt + export; no SCP03 requirement (dev/test only)
    SignOnly,    // only signing; req_Sm=1 requires SCP03 for every operation
    SignDecrypt, // sign + decrypt; req_Sm=1
};

// Operations on a single RSA key pair stored in the SE05x. Move-only.
// The destructor does NOT erase the SE-resident key object.
class RsaKey {
public:
    using SpkiDer = std::vector<uint8_t>;
    using SigBytes = std::vector<uint8_t>;
    using CsrPem = std::string;

    // Generate a fresh RSA key pair and persist it in the SE.
    static Result<RsaKey> Generate(Connection &conn, uint32_t key_id, RsaBits bits,
                                   KeyPolicy policy = KeyPolicy::Full);

    // Bind to an existing persisted RSA key.
    static Result<RsaKey> Open(Connection &conn, uint32_t key_id);

    // Sign a 32-byte SHA-256 digest (RSASSA-PKCS1-v1_5-SHA256).
    Result<SigBytes> Sign(const uint8_t *digest, size_t digest_len);

    // Verify a PKCS#1 v1.5 signature over a SHA-256 digest.
    // Returns an error if the SE hardware fails; returns false if the signature
    // is simply invalid (distinguishes hardware fault from bad signature).
    Result<bool> Verify(const uint8_t *digest, size_t digest_len,
                        const uint8_t *sig, size_t sig_len);

    // Export the RSA public key as DER SubjectPublicKeyInfo.
    Result<SpkiDer> PublicKeyDer();

    // Generate a PKCS#10 CSR signed by the SE key (the private key never leaves
    // the SE).  subject_dn is a RFC 4514 distinguished name string, e.g.
    // "CN=device-001,O=Acme,C=US".
    Result<CsrPem> MakeCsr(const char *subject_dn);

    // RSA modulus size in bytes (256 for RSA-2048, 512 for RSA-4096).
    size_t modulus_bytes() const { return bits_ / 8; }

    ~RsaKey();
    RsaKey(RsaKey &&) noexcept;
    RsaKey &operator=(RsaKey &&) = delete;
    RsaKey(const RsaKey &) = delete;
    RsaKey &operator=(const RsaKey &) = delete;

private:
    explicit RsaKey(Connection &conn) : obj_(conn), bits_(2048) {}

    KeyObject obj_;
    size_t bits_;
};

} // namespace se051
