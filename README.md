# se051 — minimal C++ library for the NXP SE05x / SE051

A small, self-contained C++17 library that wraps NXP's Plug & Trust middleware
into an ergonomic API for the SE05x / SE051 secure element. Real hardware only:
T=1 over Linux I2C (`/dev/i2c-*`) with Platform SCP03.

No ETL, no boost, no system TLS — just the standard library plus two source
dependencies fetched and built automatically (mbedTLS, NXP Plug & Trust).

## API

Include the single umbrella header and link the one target:

```cpp
#include <se051/se051.hpp>
using namespace se051;

auto conn = Connection::Open("/dev/i2c-3");
if (!conn) return 1;

auto key = RsaKey::Generate(conn.value(), kRsaKeyId, RsaBits::k2048);
auto csr = key.value().MakeCsr("CN=device-001,O=Acme");   // private key stays in the SE
```

What's available (all in `namespace se051`, results via `Result<T>` / `Status`):

| Type | Purpose |
|------|---------|
| `Connection`  | Open/close an SCP03 session to the SE. |
| `ObjectStore` | UID, object existence/type/erase, cert + binary blob I/O. |
| `RsaKey`      | RSA generate/open, sign, verify, SPKI, PKCS#10 CSR. |
| `EcKey`       | NIST-P EC generate/open, ECDSA sign/verify, CSR. |
| `SeRandom`    | Bytes from the SE hardware TRNG. |
| `Scp03Admin`  | Platform SCP03 key rotation (GP PUT KEY). |
| `SetupOpaquePk` | Bridge an SE key into an mbedTLS `pk` context for mTLS. |

## Build

```bash
cmake --preset native            # host build
cmake --build build/native
```

Cross-compile for the SigmaStar 26T-Pro (armhf, vendor gcc-11):

```bash
cmake --preset sigmastar         # uses cmake/toolchains/sigmastar-arm-linux-gnueabihf.cmake
cmake --build build/sigmastar
```

The `example_se_quickstart` program (`examples/se_quickstart`) is a guided tour
of the API — UID, TRNG, RSA + EC keygen, CSR, sign/verify, object store, and an
SCP03 rotation round-trip. It needs a real SE to run.

## Importing into another project

CMake — `add_subdirectory` (or FetchContent) and link `se051::se051`:

```cmake
add_subdirectory(third_party/se051 se051)
target_link_libraries(my_app PRIVATE se051::se051)
```

Non-CMake builds — `cmake --install` stages a single combined static archive
(`lib/libse051_combined.a`, includes the SSS + mbedTLS members) and the headers
under `include/se051/`, so you can link by path.
