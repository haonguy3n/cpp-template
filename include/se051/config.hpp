#ifndef SE051_CONFIG_HPP
#define SE051_CONFIG_HPP

// Central configuration for the se051 library. Override per-target with
// -DSE051_xxx or by editing this file in a fork.

// Maximum number of characters in one formatted log line.
#ifndef SE051_LOG_LINE_CAPACITY
#define SE051_LOG_LINE_CAPACITY 256
#endif

// Compile-time log level gate. Levels above this compile to nothing.
// 0=None 1=Error 2=Warn 3=Info 4=Debug
#ifndef SE051_LOG_LEVEL
#define SE051_LOG_LEVEL 4
#endif

// SE05x port sizing. These bound the on-stack ASN.1 scratch buffers and seed
// the initial size of the std containers in the public SE API surface.
#ifndef SE051_SE_SPKI_CAPACITY
#define SE051_SE_SPKI_CAPACITY 512    // DER SPKI for RSA-2048 ≈ 294 bytes
#endif

#ifndef SE051_SE_SIG_CAPACITY
#define SE051_SE_SIG_CAPACITY 512     // RSA-2048 sig = 256 bytes; covers up to 4096
#endif

#ifndef SE051_SE_CSR_PEM_CAPACITY
#define SE051_SE_CSR_PEM_CAPACITY 2048 // PEM CSR for RSA-2048 ≈ 1.7 kB
#endif

#ifndef SE051_SE_CERT_CAPACITY
#define SE051_SE_CERT_CAPACITY 2048   // DER cert for RSA-2048 identity
#endif

#ifndef SE051_SE_BLOB_CAPACITY
#define SE051_SE_BLOB_CAPACITY 512    // binary objects (device-info, SCP03 keys)
#endif

#ifndef SE051_SE_UID_LEN
#define SE051_SE_UID_LEN 18           // SE05x chip UID is always 18 bytes
#endif

#endif // SE051_CONFIG_HPP
