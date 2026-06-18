# Importing the SE05x support library

The secure-element support API is a normal CMake library target, `etlx::se05x`,
with a single public umbrella header:

```cpp
#include <etlx/se.hpp>
using namespace etlx::se;
```

That one include pulls in the whole surface (Connection, ObjectStore, RsaKey,
SeRandom, Scp03Admin, the mTLS opaque-pk bridge). You never need to include the
individual `etlx/se/*.hpp` headers directly.

## Consuming from another CMake project

### Option A — add_subdirectory

```cmake
set(ETLX_WITH_SE05X     ON  CACHE BOOL "" FORCE)   # implies ETLX_WITH_TLS
set(ETLX_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(ETLX_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ETLX_BUILD_DEMOCLI  OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/cpp-template etlx)

target_link_libraries(my_app PRIVATE etlx::se05x)
```

`etlx::se05x` propagates its include path and links its dependencies
(NXP plug-and-trust middleware, mbedTLS, ETL) transitively, so linking the one
target is enough.

### Option B — FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(etlx
  GIT_REPOSITORY <your-repo-url>
  GIT_TAG        <commit-or-tag>)
set(ETLX_WITH_SE05X ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(etlx)

target_link_libraries(my_app PRIVATE etlx::se05x)
```

## Picking the transport

The SE port is compiled for exactly one transport, selected at configure time
with `ETLX_SE05X_TRANSPORT`:

| value    | target                                             |
|----------|----------------------------------------------------|
| `sim`    | NXP socket / VCOM simulator (`127.0.0.1:8050`)     |
| `socket` | JRCP-over-TCP to a remote SE                        |
| `i2c`    | real hardware (e.g. `/dev/i2c-1:0x48`)             |

At runtime the connect string is passed to `Connection::Open(port)`, or read
from the `EX_SSS_BOOT_SSS_PORT` environment variable when `port` is `nullptr`.

## Minimal usage

```cpp
#include <etlx/se.hpp>
using namespace etlx::se;

auto conn = Connection::Open("127.0.0.1:8050");
if (!conn) { /* conn.error().message */ return 1; }

auto key = RsaKey::Generate(conn.value(), kRsaKeyId, RsaBits::k2048);
if (!key) return 1;

auto csr = key.value().MakeCsr("CN=device-001,O=Acme");   // private key stays in SE
```

Every call returns `etlx::Result<T>` / `etlx::Status` — no exceptions are
thrown. Check truthiness, read `.value()` on success or `.error().message` on
failure.

## Worked example

`examples/se_quickstart/main.cpp` is a complete, runnable tour of the API
through `<etlx/se.hpp>` alone: open → UID → TRNG → provision key → CSR →
sign/verify → blob round-trip. Build and run it with:

```bash
cmake --preset se05x-sim
cmake --build build/se05x-sim --target example_se_quickstart
EX_SSS_BOOT_SSS_PORT=127.0.0.1:8050 ./build/se05x-sim/examples/example_se_quickstart
```

With no port set it prints a usage note and exits 0, so it is safe in CI.
