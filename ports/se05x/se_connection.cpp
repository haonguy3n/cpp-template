#include <etlx/se/connection.hpp>
#include <etlx/se/scp03.hpp>
#include <etlx/log/log.hpp>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
#include <fsl_sss_se05x_types.h>
}

namespace etlx::se {

// SE051C part SSS_PFSCP_ENABLE_SE051C_0005A8FA.
static constexpr Scp03KeySet kDefaultKeys = {
    { 0xBF, 0xC2, 0xDB, 0xE1, 0x82, 0x8E, 0x03, 0x5D, 0x3E, 0x7F, 0xA3, 0x6B, 0x90, 0x2A, 0x05, 0xC6 },
    { 0xBE, 0xF8, 0x5B, 0xD7, 0xBA, 0x04, 0x97, 0xD6, 0x28, 0x78, 0x1C, 0xE4, 0x7B, 0x18, 0x8C, 0x96 },
    { 0xD8, 0x73, 0xF3, 0x16, 0xBE, 0x29, 0x7F, 0x2F, 0xC9, 0xC0, 0xE4, 0x5F, 0x54, 0x71, 0x06, 0x99 },
};

const Scp03KeySet &DefaultScp03Keys() { return kDefaultKeys; }

#if SSS_HAVE_SE05X_AUTH_PLATFSCP03

Result<Connection> Connection::Open(const char *port, const Scp03KeySet &keys,
                                    bool select_applet) {
    Connection c;
    auto *ctx = c.ctx_.get();
    auto *cc  = &ctx->se05x_open_ctx;

    if (!select_applet)
        cc->skip_select_applet = 1;

#if defined(T1oI2C)
    cc->connType = kType_SE_Conn_Type_T1oI2C;
    cc->portName = port;
#elif defined(SMCOM_JRCP_V1)
    cc->connType = kType_SE_Conn_Type_JRCP_V1;
    cc->portName = port;
#else
#   error "se_connection.cpp: unknown SCP03 transport — add connType mapping here"
#endif

    sss_status_t st = ex_sss_se05x_prepare_host(
        &ctx->host_session, &ctx->host_ks, cc, &ctx->ex_se05x_auth, kSSS_AuthType_SCP03);
    if (st != kStatus_SSS_Success) {
        ETLX_LOG_ERROR("se: prepare_host failed (status=0x%04x)", static_cast<unsigned>(st));
        return SeFail(kOpenFailed, "prepare_host failed");
    }

    auto *sc = cc->auth.ctx.scp03.pStatic_ctx;
    sss_host_key_store_set_key(&ctx->host_ks, &sc->Enc, keys.enc, 16, 128, NULL, 0);
    sss_host_key_store_set_key(&ctx->host_ks, &sc->Mac, keys.mac, 16, 128, NULL, 0);
    sss_host_key_store_set_key(&ctx->host_ks, &sc->Dek, keys.dek, 16, 128, NULL, 0);

    st = sss_session_open(&ctx->session, kType_SSS_SE_SE05x, 0,
                          kSSS_ConnectionType_Encrypted, cc);
    if (st != kStatus_SSS_Success) {
        ETLX_LOG_ERROR("se: sss_session_open failed (port=%s, status=0x%04x)",
                       port ? port : "(default)", static_cast<unsigned>(st));
        return SeFail(kOpenFailed, "sss_session_open failed");
    }
    c.opened_ = true;

    st = ex_sss_key_store_and_object_init(ctx);
    if (st != kStatus_SSS_Success) {
        ETLX_LOG_ERROR("se: key_store_and_object_init failed (status=0x%04x)",
                       static_cast<unsigned>(st));
        return SeFail(kStoreFailed, "ex_sss_key_store_and_object_init failed");
    }

    ETLX_LOG_INFO("se: session opened (port=%s)", port ? port : "(default)");
    return c;
}

Result<Connection> Connection::Open(const char *port, bool select_applet) {
    return Open(port, kDefaultKeys, select_applet);
}

#else // SSS_HAVE_SE05X_AUTH_NONE (sim transport - no SCP03)

Result<Connection> Connection::Open(const char *port, bool select_applet) {
    Connection c;

    if (!select_applet)
        c.ctx_->se05x_open_ctx.skip_select_applet = 1;

    sss_status_t st = ex_sss_boot_open(c.ctx_.get(), port);
    if (st != kStatus_SSS_Success) {
        ETLX_LOG_ERROR("se: ex_sss_boot_open failed (port=%s, status=0x%04x)",
                       port ? port : "(default)", static_cast<unsigned>(st));
        return SeFail(kOpenFailed, "ex_sss_boot_open failed");
    }
    c.opened_ = true;

    st = ex_sss_key_store_and_object_init(c.ctx_.get());
    if (st != kStatus_SSS_Success) {
        ETLX_LOG_ERROR("se: key_store_and_object_init failed (status=0x%04x)",
                       static_cast<unsigned>(st));
        return SeFail(kStoreFailed, "ex_sss_key_store_and_object_init failed");
    }

    ETLX_LOG_INFO("se: session opened (port=%s)", port ? port : "(default)");
    return c;
}

// The simulator build has no SCP03 auth; the key set is ignored.
Result<Connection> Connection::Open(const char *port, const Scp03KeySet &,
                                    bool select_applet) {
    return Open(port, select_applet);
}

#endif // SSS_HAVE_SE05X_AUTH_PLATFSCP03

Connection::~Connection() {
    if (opened_) {
        ex_sss_session_close(ctx_.get());
        ETLX_LOG_DEBUG("se: session closed");
    }
}

} // namespace etlx::se
