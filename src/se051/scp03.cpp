#include <se051/scp03.hpp>
#include <se051/log/log.hpp>

#include <cstring>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_se05x_types.h>
#include <se05x_tlv.h>
}

// GP / NXP constants (same guards as the original scp03_rotate.cpp).
#ifndef GP_CLA_BYTE
#define GP_CLA_BYTE 0x80
#endif
#ifndef GP_INS_PUTKEY
#define GP_INS_PUTKEY 0xD8
#endif
#ifndef GP_PUTKEY_KEYID
#define GP_PUTKEY_KEYID 0x01 // key identifier of the first key in the PUT KEY block
#endif
#ifndef PUT_KEYS_KEY_TYPE_CODING_AES
#define PUT_KEYS_KEY_TYPE_CODING_AES 0x88
#endif
#ifndef CRYPTO_KEY_CHECK_LEN
#define CRYPTO_KEY_CHECK_LEN 3
#endif

namespace se051 {

namespace {

constexpr int kKeyLen = 16; // 128-bit keys

inline NXSCP03_StaticCtx_t *StaticCtx(Connection &conn) {
    return conn.boot_ctx()->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx;
}

// Load a DEK into pStatic_ctx->Dek so genKcvAndEncryptKey can wrap the new keys
// with it.  The DEK must match what the SE currently holds.
Status SetCurrentDek(Connection &conn, const uint8_t dek[kKeyLen]) {
    NXSCP03_StaticCtx_t *sc = StaticCtx(conn);
    sc->key_len = kKeyLen;
    sss_status_t rc = sss_host_key_store_set_key(sc->Dek.keyStore, &sc->Dek, dek, kKeyLen,
                                                  kKeyLen * 8, nullptr, 0);
    if (rc != kStatus_SSS_Success)
        return SeFail(kKeyFailed, "load current DEK into static ctx failed");
    return Ok();
}

// Read the current DEK from the key file at path and load it (see SetCurrentDek).
Status LoadCurrentDek(Connection &conn, const char *path) {
    uint8_t dek[kKeyLen] = {};
    auto st = scp03_keyfile::ReadDek(path, dek);
    if (!st)
        return st;

    auto rc = SetCurrentDek(conn, dek);
    volatile uint8_t *vp = dek;
    for (int i = 0; i < kKeyLen; ++i) vp[i] = 0; // scrub
    return rc;
}

// KCV = AES-CBC(plainKey, IV=0, {0x01}*16)[0:3]
// encOut = AES-CBC(currentDEK, IV=0, plainKey)
Status GenKcvAndEncryptKey(Connection &conn, const uint8_t *plain_key,
                            uint8_t enc_out[kKeyLen],
                            uint8_t kcv_out[CRYPTO_KEY_CHECK_LEN]) {
    ex_sss_boot_ctx_t *ctx = conn.boot_ctx();
    NXSCP03_StaticCtx_t *sc = StaticCtx(conn);
    static constexpr uint32_t kScratchId = 0x544D5031; // "TMP1"

    sss_object_t keyObj{};
    sss_symmetric_t symm{};
    uint8_t iv[16] = {};

    auto fail = [&](SeError code, const char *msg) -> Status {
        if (symm.keyObject) sss_host_symmetric_context_free(&symm);
        sss_host_key_object_free(&keyObj);
        return SeFail(code, msg);
    };

    if (sss_host_key_object_init(&keyObj, &ctx->host_ks) != kStatus_SSS_Success)
        return SeFail(kKeyFailed, "host key_object_init");
    if (sss_host_key_object_allocate_handle(&keyObj, kScratchId, kSSS_KeyPart_Default,
                                             kSSS_CipherType_AES, kKeyLen,
                                             kKeyObject_Mode_Transient) != kStatus_SSS_Success)
        return fail(kKeyFailed, "host key_object_allocate_handle");

    // 1) KCV: encrypt {0x01...} with plain_key
    uint8_t ones[kKeyLen];
    std::memset(ones, 1, sizeof(ones));
    uint8_t kcv_full[kKeyLen] = {};
    if (sss_host_key_store_set_key(&ctx->host_ks, &keyObj, plain_key, kKeyLen, kKeyLen * 8,
                                    nullptr, 0) != kStatus_SSS_Success)
        return fail(kKeyFailed, "set plain key (KCV)");
    if (sss_host_symmetric_context_init(&symm, &ctx->host_session, &keyObj,
                                         kAlgorithm_SSS_AES_CBC,
                                         kMode_SSS_Encrypt) != kStatus_SSS_Success)
        return fail(kKeyFailed, "symm_init (KCV)");
    if (sss_host_cipher_one_go(&symm, iv, sizeof(iv), ones, kcv_full,
                                kKeyLen) != kStatus_SSS_Success)
        return fail(kKeyFailed, "cipher (KCV)");
    std::memcpy(kcv_out, kcv_full, CRYPTO_KEY_CHECK_LEN);

    // 2) Wrap plain_key with current DEK
    uint8_t dek[kKeyLen] = {};
    size_t dek_len = sizeof(dek), dek_bits = sizeof(dek) * 8;
    if (sss_host_key_store_get_key(&ctx->host_ks, &sc->Dek, dek, &dek_len,
                                    &dek_bits) != kStatus_SSS_Success)
        return fail(kKeyFailed, "get current DEK");
    if (sss_host_key_store_set_key(&ctx->host_ks, &keyObj, dek, sc->key_len,
                                    static_cast<size_t>(sc->key_len) * 8, nullptr,
                                    0) != kStatus_SSS_Success)
        return fail(kKeyFailed, "set DEK");
    if (sss_host_symmetric_context_init(&symm, &ctx->host_session, &keyObj,
                                         kAlgorithm_SSS_AES_CBC,
                                         kMode_SSS_Encrypt) != kStatus_SSS_Success)
        return fail(kKeyFailed, "symm_init (wrap)");
    if (sss_host_cipher_one_go(&symm, iv, sizeof(iv), plain_key, enc_out,
                                kKeyLen) != kStatus_SSS_Success)
        return fail(kKeyFailed, "cipher (wrap)");

    volatile uint8_t *vp = dek;
    for (int i = 0; i < kKeyLen; ++i) vp[i] = 0;
    sss_host_symmetric_context_free(&symm);
    sss_host_key_object_free(&keyObj);
    return Ok();
}

// Build one GP key block and return bytes written; copies KCV to kcv_out.
// Layout: [0x88][key_len+1][key_len][enc(key)][CRYPTO_KEY_CHECK_LEN][kcv]
Result<size_t> CreateKeyData(Connection &conn, const uint8_t *key, uint8_t *dst,
                              uint8_t kcv_out[CRYPTO_KEY_CHECK_LEN]) {
    dst[0] = PUT_KEYS_KEY_TYPE_CODING_AES;
    dst[1] = kKeyLen + 1;
    dst[2] = kKeyLen;
    auto st = GenKcvAndEncryptKey(conn, key, &dst[3], kcv_out);
    if (!st) return Unexpected<>{st.error()};
    dst[3 + kKeyLen] = CRYPTO_KEY_CHECK_LEN;
    std::memcpy(&dst[3 + kKeyLen + 1], kcv_out, CRYPTO_KEY_CHECK_LEN);
    return static_cast<size_t>(3 + kKeyLen + 1 + CRYPTO_KEY_CHECK_LEN); // 23
}

// Core PUT KEY send-and-verify.
Status SendPutKey(Connection &conn, const Scp03KeySet &new_keys) {
    NXSCP03_StaticCtx_t *sc = StaticCtx(conn);
    const uint8_t key_ver = sc->keyVerNo;

    auto *dyn = conn.boot_ctx()->se05x_open_ctx.auth.ctx.scp03.pDyn_ctx;
    const unsigned sec_level = dyn ? dyn->SecurityLevel : 0xFF;
    SE051_LOG_DEBUG("se: SCP03 SecurityLevel=0x%02x (need 0x33)", sec_level);
    if (sec_level != 0x33) {
        SE051_LOG_ERROR("se: SCP03 level 0x%02x insufficient; need full security (0x33)",
                       sec_level);
        return SeFail(kKeyFailed, "SCP03 security level insufficient for PUT KEY");
    }

    uint8_t cmd[128] = {};
    size_t len = 0;
    cmd[len++] = key_ver;

    uint8_t expected[1 + 3 * CRYPTO_KEY_CHECK_LEN] = {};
    size_t exp_len = 0;
    expected[exp_len++] = key_ver;

    const uint8_t *keys[3] = {new_keys.enc, new_keys.mac, new_keys.dek};
    for (const uint8_t *k : keys) {
        uint8_t kcv[CRYPTO_KEY_CHECK_LEN];
        auto res = CreateKeyData(conn, k, &cmd[len], kcv);
        if (!res) return Unexpected<>{res.error()};
        len += res.value();
        std::memcpy(&expected[exp_len], kcv, CRYPTO_KEY_CHECK_LEN);
        exp_len += CRYPTO_KEY_CHECK_LEN;
    }

    // GP PUT KEY header. P1 = key version number being replaced. P2 = key
    // identifier of the first key in the block (0x01) with b8 (0x80) set to mark
    // a multi-key block. P2 is NOT the key version (that lives in P1) — using
    // key_ver here yields SW 0x6A86 (incorrect P1/P2) on cards whose KVN != 1.
    auto *se_session = reinterpret_cast<sss_se05x_session_t *>(conn.session());
    const uint8_t p2 = static_cast<uint8_t>(0x80u | GP_PUTKEY_KEYID);
    const tlvHeader_t hdr = {{GP_CLA_BYTE, GP_INS_PUTKEY, key_ver, p2}};
    uint8_t rsp[64] = {};
    size_t rsp_len = sizeof(rsp);

    SE051_LOG_DEBUG("se: PUT KEY P1(KVN)=0x%02x P2=0x%02x len=%zu", key_ver, p2, len);
    smStatus_t txr = DoAPDUTxRx_s_Case4(&se_session->s_ctx, &hdr, cmd, len, rsp, &rsp_len);
    if (txr != SM_OK) {
        SE051_LOG_ERROR("se: PUT KEY transport failed (SW=0x%04x)", static_cast<unsigned>(txr));
        return SeFail(kKeyFailed, "PUT KEY transport failed");
    }
    if (rsp_len < exp_len + 2)
        return SeFail(kKeyFailed, "PUT KEY response too short");

    smStatus_t sw = static_cast<smStatus_t>((rsp[rsp_len - 2] << 8) | rsp[rsp_len - 1]);
    if (sw != SM_OK) {
        SE051_LOG_ERROR("se: PUT KEY rejected (SW=0x%04x)", static_cast<unsigned>(sw));
        return SeFail(kKeyFailed, "PUT KEY rejected by SE");
    }
    if (std::memcmp(rsp, expected, exp_len) != 0) {
        SE051_LOG_ERROR("se: PUT KEY KCV mismatch — rotation NOT confirmed");
        return SeFail(kKeyFailed, "PUT KEY key-check-value mismatch");
    }

    SE051_LOG_INFO("se: PlatformSCP03 keys rotated at version 0x%02x", key_ver);
    return Ok();
}

} // namespace

Status Scp03Admin::Rotate(const Scp03KeySet &new_keys, bool dry_run, const char *key_file) {
    // If we need to wrap the new keys we must first load the current DEK.
    if (!dry_run) {
        const char *path = key_file ? key_file : std::getenv("EX_SSS_BOOT_SCP03_PATH");
        if (!path || !*path)
            return SeFail(kKeyFailed, "SCP03 key file path unknown (set EX_SSS_BOOT_SCP03_PATH)");
        auto st = LoadCurrentDek(conn_, path);
        if (!st) return st;
    }

    if (dry_run) {
        SE051_LOG_INFO("se: SCP03 rotate dry-run: key blocks built, not sent");
        return Ok();
    }

    auto st = SendPutKey(conn_, new_keys);
    if (!st) return st;

    if (key_file) {
        auto wst = scp03_keyfile::Write(key_file, new_keys);
        if (!wst) {
            SE051_LOG_ERROR("se: key rotation succeeded but key file write failed!");
            return wst;
        }
    }
    return Ok();
}

Status Scp03Admin::Rotate(const Scp03KeySet &current_keys, const Scp03KeySet &new_keys,
                          bool dry_run) {
    if (auto st = SetCurrentDek(conn_, current_keys.dek); !st)
        return st;
    if (dry_run) {
        SE051_LOG_INFO("se: SCP03 rotate dry-run (in-memory): key blocks built, not sent");
        return Ok();
    }
    return SendPutKey(conn_, new_keys);
}

} // namespace se051
