#pragma once
// Internal PKCS#10 CSR assembly shared by the RSA and EC key ports. Builds the
// CertificationRequestInfo and wraps it with a signature into a PEM CSR. The
// signature algorithm OID is supplied by the caller so the same ASN.1 code
// serves both sha256WithRSAEncryption and ecdsa-with-SHA256.

#include <cstddef>
#include <cstdint>

namespace se051::detail {

// Build DER CertificationRequestInfo into buf[0..buf_size), writing backwards
// from buf+buf_size. Returns bytes written (the CRI lives at the END of buf) or
// <0 on error.
int BuildCri(uint8_t *buf, size_t buf_size, const char *subject_dn,
             const uint8_t *spki, size_t spki_len);

// Assemble the DER CertificationRequest from the CRI + signature and PEM-encode
// it into pem_out. sig_oid/sig_oid_len identify the signatureAlgorithm.
bool AssembleCsr(const uint8_t *cri, size_t cri_len,
                 const uint8_t *sig, size_t sig_len,
                 const char *sig_oid, size_t sig_oid_len,
                 char *pem_out, size_t pem_capacity);

} // namespace se051::detail
