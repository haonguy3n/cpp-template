// Example: SE05x quickstart — a guided tour of the etlx SE support API.
//
// Imports the entire SE surface through the single umbrella header
// <etlx/se.hpp> and exercises the common operations end to end:
//
//   1. Open a Connection to the secure element.
//   2. Read the 18-byte chip UID.
//   3. Pull random bytes from the SE hardware TRNG (SeRandom).
//   4. Provision an RSA key (generate, or open an existing one).
//   5. Build a PKCS#10 CSR for that key.
//   6. Sign a 32-byte digest and verify it back (private key never leaves SE).
//   7. Write a small device-info blob and read it back (ObjectStore).
//
// Requires: ETLX_WITH_SE05X=ON (which implies ETLX_WITH_TLS=ON).
//
// Run against the NXP socket simulator or real hardware:
//   EX_SSS_BOOT_SSS_PORT=127.0.0.1:8050 ./example_se_quickstart
//   ./example_se_quickstart 127.0.0.1:8050        # port as argv[1]
//
// If no port is given and EX_SSS_BOOT_SSS_PORT is unset, the example prints a
// usage note and exits 0 (so it is safe to run in a no-hardware CI smoke test).

#include <etlx/se.hpp>
#include <etlx/log/log.hpp>
#include "host/host_io.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>

using namespace etlx;
using namespace etlx::se;

namespace {

// A throwaway object ID for the blob round-trip so the demo never clobbers a
// real device-info object.
constexpr uint32_t kDemoBlobId = 0xFE0000A0u;

void PrintHex(const char *label, const uint8_t *p, size_t n) {
    std::printf("%s (%zu bytes): ", label, n);
    for (size_t i = 0; i < n; ++i) std::printf("%02x", p[i]);
    std::putchar('\n');
}

const char *TypeName(ObjectType t) {
    switch (t) {
    case ObjectType::Binary:      return "binary";
    case ObjectType::Certificate: return "certificate";
    case ObjectType::Rsa:         return "RSA key";
    case ObjectType::Ecc:         return "ECC key";
    case ObjectType::Symmetric:   return "symmetric key";
    default:                      return "other";
    }
}

} // namespace

int main(int argc, char **argv) {
    static ports::host::StderrLogSink sink;
    log::SetSink(&sink);
    log::SetLevel(log::Level::Info);

    const char *port = (argc > 1) ? argv[1] : std::getenv("EX_SSS_BOOT_SSS_PORT");
    if (port == nullptr) {
        std::puts("se_quickstart: no SE port given.\n"
                  "  usage: example_se_quickstart <port>\n"
                  "  or set EX_SSS_BOOT_SSS_PORT (e.g. 127.0.0.1:8050)");
        return 0;
    }

    // 1. Open the session. RAII: the SE is closed when `conn` goes out of scope.
    auto conn_res = Connection::Open(port);
    if (!conn_res) {
        ETLX_LOG_ERROR("open: %s", conn_res.error().message.c_str());
        return 1;
    }
    Connection &conn = conn_res.value();
    ETLX_LOG_INFO("se_quickstart: connected to %s", port);

    ObjectStore store(conn);

    // 2. Chip UID.
    if (auto uid = store.GetUid()) {
        PrintHex("UID", uid.value().data(), uid.value().size());
    } else {
        ETLX_LOG_ERROR("uid: %s", uid.error().message.c_str());
        return 1;
    }

    // 3. Hardware TRNG via the etlx::crypto::Random interface.
    SeRandom rng(conn);
    uint8_t nonce[32];
    if (auto st = rng.Fill(ByteSpan{nonce, sizeof(nonce)}); !st) {
        ETLX_LOG_ERROR("rng: %s", st.error().message.c_str());
        return 1;
    }
    PrintHex("TRNG nonce", nonce, sizeof(nonce));

    // 4. Provision: open the existing key, or generate one if absent.
    Result<RsaKey> key_res = SeFail(kKeyFailed, "uninitialised");
    if (store.Exists(kRsaKeyId)) {
        ETLX_LOG_INFO("se_quickstart: opening existing key 0x%08x",
                      static_cast<unsigned>(kRsaKeyId));
        key_res = RsaKey::Open(conn, kRsaKeyId);
    } else {
        ETLX_LOG_INFO("se_quickstart: generating RSA-2048 key 0x%08x",
                      static_cast<unsigned>(kRsaKeyId));
        key_res = RsaKey::Generate(conn, kRsaKeyId, RsaBits::k2048, KeyPolicy::Full);
    }
    if (!key_res) {
        ETLX_LOG_ERROR("key: %s", key_res.error().message.c_str());
        return 1;
    }
    RsaKey &key = key_res.value();

    // Inspect what kind of object now occupies the slot.
    if (auto t = store.GetType(kRsaKeyId))
        std::printf("slot 0x%08x type: %s\n",
                    static_cast<unsigned>(kRsaKeyId), TypeName(t.value()));

    // 5. CSR (PKCS#10) — private key stays in the SE; only the request leaves.
    if (auto csr = key.MakeCsr("CN=se-quickstart,O=Iritech")) {
        std::printf("\n%s\n", csr.value().c_str());
    } else {
        ETLX_LOG_ERROR("csr: %s", csr.error().message.c_str());
        return 1;
    }

    // 6. Sign the 32-byte nonce as if it were a SHA-256 digest, then verify.
    auto sig = key.Sign(nonce, sizeof(nonce));
    if (!sig) {
        ETLX_LOG_ERROR("sign: %s", sig.error().message.c_str());
        return 1;
    }
    ETLX_LOG_INFO("se_quickstart: signature %zu bytes", sig.value().size());

    auto ok = key.Verify(nonce, sizeof(nonce), sig.value().data(), sig.value().size());
    if (!ok) {
        ETLX_LOG_ERROR("verify: %s", ok.error().message.c_str());
        return 1;
    }
    std::printf("signature self-check: %s\n", ok.value() ? "VALID" : "INVALID");

    // 7. Object store round-trip: write a small blob and read it back.
    const uint8_t info[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    if (auto w = store.WriteBinary(kDemoBlobId, info, sizeof(info), /*force=*/true); !w) {
        ETLX_LOG_ERROR("write-blob: %s", w.error().message.c_str());
        return 1;
    }
    if (auto t = store.GetType(kDemoBlobId))
        std::printf("slot 0x%08x type: %s\n",
                    static_cast<unsigned>(kDemoBlobId), TypeName(t.value()));
    if (auto r = store.ReadBinary(kDemoBlobId)) {
        PrintHex("blob read-back", r.value().data(), r.value().size());
    } else {
        ETLX_LOG_ERROR("read-blob: %s", r.error().message.c_str());
        return 1;
    }
    // Leave the SE as we found it.
    if (auto e = store.Erase(kDemoBlobId); !e)
        ETLX_LOG_WARN("cleanup: %s", e.error().message.c_str());

    ETLX_LOG_INFO("se_quickstart: done");
    return 0;
}
