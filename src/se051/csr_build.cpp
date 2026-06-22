#include "csr_build.hpp"

#include <se051/config.hpp>

#include <cstring>

extern "C" {
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509.h"
}

// mbedtls_x509_write_names was removed from the public header in mbedTLS 3.x
// but is still compiled into the library (library/x509_create.c). We need it to
// encode the subject DN into the CertificationRequestInfo.
extern "C" int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                                         mbedtls_asn1_named_data *first);

namespace se051::detail {

#define CHK(expr)                           \
    do {                                    \
        int _r = (expr);                    \
        if (_r < 0) return _r;              \
        written += _r;                      \
    } while (0)

int BuildCri(uint8_t *buf, size_t buf_size, const char *subject_dn,
             const uint8_t *spki, size_t spki_len) {
    unsigned char *start = buf;
    unsigned char *c = buf + buf_size;
    int written = 0;

    mbedtls_asn1_named_data *names = nullptr;
    if (mbedtls_x509_string_to_names(&names, subject_dn) != 0)
        return -1;

    // attributes [0] -- empty SET
    CHK(mbedtls_asn1_write_len(&c, start, 0));
    CHK(mbedtls_asn1_write_tag(&c, start,
        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0));

    // subjectPKInfo
    if (static_cast<size_t>(c - start) < spki_len) {
        mbedtls_asn1_free_named_data_list(&names);
        return -1;
    }
    c -= spki_len;
    std::memcpy(c, spki, spki_len);
    written += static_cast<int>(spki_len);

    // subject Name
    int r = mbedtls_x509_write_names(&c, start, names);
    mbedtls_asn1_free_named_data_list(&names);
    if (r < 0) return r;
    written += r;

    // version INTEGER 0
    CHK(mbedtls_asn1_write_int(&c, start, 0));

    // wrap in SEQUENCE
    CHK(mbedtls_asn1_write_len(&c, start, written));
    CHK(mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return written;
}

bool AssembleCsr(const uint8_t *cri, size_t cri_len,
                 const uint8_t *sig, size_t sig_len,
                 const char *sig_oid, size_t sig_oid_len,
                 char *pem_out, size_t pem_capacity) {
    uint8_t buf[SE051_SE_CSR_PEM_CAPACITY];
    unsigned char * const start = buf;
    unsigned char *c = buf + sizeof(buf);
    int written = 0;
#define CHKB(expr) do { int _r = (expr); if (_r < 0) return false; written += _r; } while (0)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    CHKB(mbedtls_asn1_write_bitstring(&c, start,
        reinterpret_cast<const unsigned char *>(sig), sig_len * 8));
#pragma GCC diagnostic pop

    // signatureAlgorithm (caller-supplied OID).
    {
        int ar = mbedtls_asn1_write_algorithm_identifier(&c, start, sig_oid, sig_oid_len, 0);
        if (ar < 0) return false;
        written += ar;
    }

    if (static_cast<size_t>(c - start) < cri_len) return false;
    c -= cri_len;
    std::memcpy(c, cri, cri_len);
    written += static_cast<int>(cri_len);

    CHKB(mbedtls_asn1_write_len(&c, start, written));
    CHKB(mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
#undef CHKB

    size_t olen = 0;
    int r = mbedtls_pem_write_buffer(
        "-----BEGIN CERTIFICATE REQUEST-----\n",
        "-----END CERTIFICATE REQUEST-----\n",
        c, written, reinterpret_cast<unsigned char *>(pem_out), pem_capacity, &olen);
    return (r == 0);
}

#undef CHK

} // namespace se051::detail
