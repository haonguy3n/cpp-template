#pragma once

#include <se051/core/error.hpp>
#include <se051/core/result.hpp>

#include <cstdint>
#include <cstring>
#include <memory>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
}

namespace se051 {

struct Scp03KeySet; // defined in scp03.hpp

inline constexpr error::Category kSeCategory{"se051"};

enum SeError : int {
    kOpenFailed  = 1,
    kStoreFailed = 2,
    kRngFailed   = 3,
    kKeyFailed   = 4,
    kSignFailed  = 5,
    kWriteFailed = 6,
    kReadFailed  = 7,
};

// Returns an Unexpected<error::Error> wrapping an SE error (compatible with
// both Result<T> and Status returns in C++17 without CTAD through alias).
inline Unexpected<> SeFail(SeError code, std::string_view msg) {
    return Fail(kSeCategory, static_cast<error::Code>(code), msg);
}

// RAII owner of the SSS boot context lifecycle (open + keystore init + close).
// Non-copyable; move-only so it can be returned from the Open() factory.
//
// This is a hosted-OS class (heap/OS calls are acceptable) matching the
// ports/asio design — it is NOT compiled with etlx_embedded_flags.
class Connection {
public:
    // Open a connection to the SE05x and initialise the key store.
    // port: connect string understood by ex_sss_boot_open (e.g.
    //   "127.0.0.1:8050" for the NXP VCOM/socket simulator, or a real I2C
    //   device path like "/dev/i2c-1:0x48").  nullptr uses the middleware
    //   default (reads EX_SSS_BOOT_SSS_PORT env var).
    // select_applet: pass false when targeting the ISD channel for SCP03
    //   key rotation — the card manager must be reached without selecting
    //   the SE05x applet first.
    static Result<Connection> Open(const char *port, bool select_applet = true);

    // Open authenticating with an explicit Platform SCP03 key set instead of the
    // compiled-in defaults — needed to reconnect after a key rotation (the SE
    // only accepts the new keys on the next session).  On the no-auth simulator
    // build the key set is ignored.
    static Result<Connection> Open(const char *port, const Scp03KeySet &keys,
                                   bool select_applet = true);

    ~Connection();

    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;

    Connection(Connection &&o) noexcept
        : ctx_(std::move(o.ctx_)), opened_(std::exchange(o.opened_, false)) {}
    Connection &operator=(Connection &&) = delete;

    sss_session_t *session() { return &ctx_->session; }
    sss_key_store_t *keystore() { return &ctx_->ks; }
    ex_sss_boot_ctx_t *boot_ctx() { return ctx_.get(); }

private:
    Connection() : ctx_(std::make_unique<ex_sss_boot_ctx_t>()) {}

    std::unique_ptr<ex_sss_boot_ctx_t> ctx_;
    bool opened_ = false;
};

} // namespace se051
