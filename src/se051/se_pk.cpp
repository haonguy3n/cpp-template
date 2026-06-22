#include <se051/se_pk.hpp>

#include <cstring>

extern "C" {
#include <mbedtls/pk.h>
}

namespace se051 {

namespace {

int SeSign(void *ctx,
           int (*)(void *, unsigned char *, size_t), void *,
           mbedtls_md_type_t, unsigned int hashlen,
           const unsigned char *hash, unsigned char *sig) {
    auto res = static_cast<RsaKey *>(ctx)->Sign(hash, hashlen);
    if (!res) return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    const auto &sv = res.value();
    std::memcpy(sig, sv.data(), sv.size());
    return 0;
}

int SeDecrypt(void *, size_t *, const unsigned char *, unsigned char *, size_t) {
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}

size_t SeKeyLen(void *ctx) {
    return static_cast<RsaKey *>(ctx)->modulus_bytes();
}

} // namespace

Status SetupOpaquePk(mbedtls_pk_context &pk, RsaKey &key) {
    int r = mbedtls_pk_setup_rsa_alt(&pk, &key, SeDecrypt, SeSign, SeKeyLen);
    if (r != 0)
        return SeFail(kKeyFailed, "mbedtls_pk_setup_rsa_alt failed");
    return Ok();
}

} // namespace se051
