#pragma once

#include <se051/rsa_key.hpp>
#include <mbedtls/pk.h>

namespace se051 {

// Wire a SE-resident RSA key into a mbedTLS pk context so it can serve as the
// client private key in a TlsSocket mTLS handshake.  All signing is performed
// inside the SE — the private key never leaves the chip.
//
// Preconditions: pk must be mbedtls_pk_init'd, key must outlive pk.
Status SetupOpaquePk(mbedtls_pk_context &pk, RsaKey &key);

} // namespace se051
