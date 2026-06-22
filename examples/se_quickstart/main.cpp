// Example: SE05x quickstart — a guided tour of the se051 SE support API.
//
// Imports the entire SE surface through the single umbrella header
// <se051/se051.hpp> and exercises the common operations end to end:
//
//   1. Open a Connection to the secure element.
//   2. Read the 18-byte chip UID.
//   3. Pull random bytes from the SE hardware TRNG (SeRandom).
//   4. Provision an RSA key (generate, or open an existing one).
//   5-6. For the RSA key and an EC P-256 key: report the slot type, build a
//      PKCS#10 CSR, sign a 32-byte digest and verify it (key never leaves SE).
//   7. Write a small device-info blob and read it back (ObjectStore).
//   8. SCP03 key rotation round-trip: rotate to a hardcoded new key set and,
//      on success, rotate back to the default keys (PlatformSCP03 builds only).
//
// Requires a real SE05x / SE051 reached over Linux I2C (/dev/i2c-*).
//
//   ./example_se_quickstart                # defaults to /dev/i2c-3
//   ./example_se_quickstart /dev/i2c-3     # I2C device as argv[1]
//
// Port precedence: argv[1] > EX_SSS_BOOT_SSS_PORT > /dev/i2c-3.

#include <se051/se051.hpp>
#include <se051/log/log.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>

// SCP03 rotation only exists on the PlatformSCP03 (i2c) build; the no-auth
// simulator build has no SCP03 static context to rotate.
#if defined(SSS_HAVE_SE05X_AUTH_PLATFSCP03) && SSS_HAVE_SE05X_AUTH_PLATFSCP03
#define SE051_QS_HAVE_SCP03 1
#else
#define SE051_QS_HAVE_SCP03 0
#endif

using namespace se051;

namespace {

class StderrLogSink final : public log::Sink {
public:
    void Write(log::Level level, std::string_view line) override {
        const char *lvl = level == log::Level::Error ? "ERROR"
                        : level == log::Level::Warn  ? "WARN"
                        : level == log::Level::Debug ? "DEBUG" : "INFO";
        std::fprintf(stderr, "[%s] %.*s\n", lvl,
                     static_cast<int>(line.size()), line.data());
    }
};

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

template <class Key>
int ExerciseAsymKey(ObjectStore &store, Key &key, uint32_t slot,
                    const char *subject, const uint8_t *digest, size_t digest_len) {
    if (auto t = store.GetType(slot))
        SE051_LOG_INFO("slot 0x%08x type: %s", static_cast<unsigned>(slot), TypeName(t.value()));

    // CSR (PKCS#10) — private key stays in the SE; only the request leaves.
    if (auto csr = key.MakeCsr(subject)) {
        SE051_LOG_INFO("\n%s", csr.value().c_str());
    } else {
        SE051_LOG_ERROR("csr: %s", csr.error().message.c_str());
        return 1;
    }

    auto sig = key.Sign(digest, digest_len);
    if (!sig) {
        SE051_LOG_ERROR("sign: %s", sig.error().message.c_str());
        return 1;
    }
    SE051_LOG_INFO("signature %zu bytes", sig.value().size());

    auto ok = key.Verify(digest, digest_len, sig.value().data(), sig.value().size());
    if (!ok) {
        SE051_LOG_ERROR("verify: %s", ok.error().message.c_str());
        return 1;
    }
    SE051_LOG_INFO("signature self-check: %s", ok.value() ? "VALID" : "INVALID");
    return 0;
}

// Steps 1-7: the applet-session API tour. Returns 0 on success.
int RunTour(const char *port) {
    // 1. Open the session. RAII: the SE is closed when `conn` goes out of scope.
    auto conn_res = Connection::Open(port);
    if (!conn_res) {
        SE051_LOG_ERROR("open: %s", conn_res.error().message.c_str());
        return 1;
    }
    Connection &conn = conn_res.value();
    SE051_LOG_INFO("se_quickstart: connected to %s", port);

    ObjectStore store(conn);

    // 2. Chip UID.
    if (auto uid = store.GetUid()) {
        PrintHex("UID", uid.value().data(), uid.value().size());
    } else {
        SE051_LOG_ERROR("uid: %s", uid.error().message.c_str());
        return 1;
    }

    // 3. Hardware TRNG via the se051::crypto::Random interface.
    SeRandom rng(conn);
    uint8_t nonce[32];
    if (auto st = rng.Fill(nonce, sizeof(nonce)); !st) {
        SE051_LOG_ERROR("rng: %s", st.error().message.c_str());
        return 1;
    }
    PrintHex("TRNG nonce", nonce, sizeof(nonce));

    // 4. Provision: open the existing key, or generate one if absent.
    Result<RsaKey> key_res = SeFail(kKeyFailed, "uninitialised");
    if (store.Exists(kRsaKeyId)) {
        SE051_LOG_INFO("se_quickstart: opening existing key 0x%08x",
                      static_cast<unsigned>(kRsaKeyId));
        key_res = RsaKey::Open(conn, kRsaKeyId);
    } else {
        SE051_LOG_INFO("se_quickstart: generating RSA-2048 key 0x%08x",
                      static_cast<unsigned>(kRsaKeyId));
        key_res = RsaKey::Generate(conn, kRsaKeyId, RsaBits::k2048, KeyPolicy::Full);
    }
    if (!key_res) {
        SE051_LOG_ERROR("key: %s", key_res.error().message.c_str());
        return 1;
    }
    RsaKey &rsa = key_res.value();

    // 5-6. RSA: slot type, CSR, sign + verify.
    SE051_LOG_INFO("se_quickstart: --- RSA key 0x%08x ---", static_cast<unsigned>(kRsaKeyId));
    if (int rc = ExerciseAsymKey(store, rsa, kRsaKeyId, "CN=se-quickstart-rsa,O=Iritech",
                                 nonce, sizeof(nonce)); rc != 0)
        return rc;

    // 6b. EC (NIST P-256): same flow with an ECDSA key.
    SE051_LOG_INFO("se_quickstart: --- EC key 0x%08x ---", static_cast<unsigned>(kEcKeyId));
    Result<EcKey> ec_res = SeFail(kKeyFailed, "uninitialised");
    if (store.Exists(kEcKeyId)) {
        SE051_LOG_INFO("se_quickstart: opening existing EC key 0x%08x",
                      static_cast<unsigned>(kEcKeyId));
        ec_res = EcKey::Open(conn, kEcKeyId);
    } else {
        SE051_LOG_INFO("se_quickstart: generating EC P-256 key 0x%08x",
                      static_cast<unsigned>(kEcKeyId));
        ec_res = EcKey::Generate(conn, kEcKeyId, EcCurve::P256, KeyPolicy::Full);
    }
    if (!ec_res) {
        SE051_LOG_ERROR("ec key: %s", ec_res.error().message.c_str());
        return 1;
    }
    if (int rc = ExerciseAsymKey(store, ec_res.value(), kEcKeyId, "CN=se-quickstart-ec,O=Iritech",
                                 nonce, sizeof(nonce)); rc != 0)
        return rc;

    // 7. Object store round-trip: write a small blob and read it back.
    const uint8_t info[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    if (auto w = store.WriteBinary(kDemoBlobId, info, sizeof(info), /*force=*/true); !w) {
        SE051_LOG_ERROR("write-blob: %s", w.error().message.c_str());
        return 1;
    }
    if (auto t = store.GetType(kDemoBlobId))
        SE051_LOG_INFO("slot 0x%08x type: %s\n",
                    static_cast<unsigned>(kDemoBlobId), TypeName(t.value()));
    if (auto r = store.ReadBinary(kDemoBlobId)) {
        PrintHex("blob read-back", r.value().data(), r.value().size());
    } else {
        SE051_LOG_ERROR("read-blob: %s", r.error().message.c_str());
        return 1;
    }
    // Leave the SE as we found it.
    if (auto e = store.Erase(kDemoBlobId); !e)
        SE051_LOG_WARN("cleanup: %s", e.error().message.c_str());

    return 0;
}

#if SE051_QS_HAVE_SCP03
// Demo key set to rotate TO. Distinct from the defaults; the demo restores the
// defaults afterwards. (Demo only — never ship real SCP03 keys in source.)
const Scp03KeySet kDemoNewKeys = {
    {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F},
};

// One rotation in its OWN ISD session: authenticate with `auth` (the keys the SE
// currently holds, whose DEK wraps the new keys), PUT KEY `target`, then close.
// The SE05x drops the secure channel after rotating its own keys, so a second
// PUT KEY in the same session is rejected (SW 0x6982) — each rotation must run
// in a fresh session opened with the current keys.
Status RotateOnce(const char *port, const Scp03KeySet &auth, const Scp03KeySet &target) {
    auto conn_res = Connection::Open(port, auth, /*select_applet=*/false);
    if (!conn_res) return Unexpected<>{conn_res.error()};
    Scp03Admin admin(std::move(conn_res.value()));
    return admin.Rotate(auth, target);
}

// 8. Round-trip: default -> new (one session), then new -> default (another).
int RunRotateRoundtrip(const char *port) {
    SE051_LOG_INFO("rotate: default -> new");
    if (auto st = RotateOnce(port, DefaultScp03Keys(), kDemoNewKeys); !st) {
        SE051_LOG_ERROR("rotate to new failed (SE keys unchanged): %s",
                       st.error().message.c_str());
        return 1;
    }
    SE051_LOG_INFO("rotate: new -> default (restore, fresh session)");
    if (auto st = RotateOnce(port, kDemoNewKeys, DefaultScp03Keys()); !st) {
        SE051_LOG_ERROR("rotate BACK FAILED — SE holds the NEW keys, "
                       "reconnect with the demo keys to restore: %s",
                       st.error().message.c_str());
        return 1;
    }
    SE051_LOG_INFO("rotate: round-trip OK — SE restored to default keys");
    return 0;
}
#endif // SE051_QS_HAVE_SCP03

} // namespace

int main(int argc, char **argv) {
    static StderrLogSink sink;
    log::SetSink(&sink);
    // SE_DEBUG=1 raises se051 logging to Debug (e.g. PUT KEY P1/P2, object IDs).
    log::SetLevel(std::getenv("SE_DEBUG") ? log::Level::Debug : log::Level::Info);

    // Port: argv[1], else EX_SSS_BOOT_SSS_PORT, else the on-device I2C default.
    const char *port = (argc > 1) ? argv[1] : std::getenv("EX_SSS_BOOT_SSS_PORT");
    if (port == nullptr)
        port = "/dev/i2c-3";

    if (int rc = RunTour(port); rc != 0)
        return rc;

#if SE051_QS_HAVE_SCP03
    if (int rc = RunRotateRoundtrip(port); rc != 0)
        return rc;
#else
    std::puts("se_quickstart: SCP03 rotation needs the i2c (PlatformSCP03) "
              "build; skipped on this transport.");
#endif

    SE051_LOG_INFO("se_quickstart: done");
    return 0;
}
