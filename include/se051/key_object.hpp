#pragma once

#include <se051/connection.hpp>

extern "C" {
#include <fsl_sss_api.h>
}

namespace se051 {

// RAII over a single sss_object_t handle (the host-side context object; does
// NOT erase the persisted SE object on destruction). Move-only.
class KeyObject {
public:
    explicit KeyObject(Connection &conn) : conn_(conn) {
        sss_key_object_init(&obj_, conn_.keystore());
        live_ = true;
    }

    ~KeyObject() {
        if (live_)
            sss_key_object_free(&obj_);
    }

    KeyObject(KeyObject &&o) noexcept : conn_(o.conn_), obj_(o.obj_), live_(o.live_) {
        o.live_ = false;
    }
    KeyObject &operator=(KeyObject &&) = delete;
    KeyObject(const KeyObject &) = delete;
    KeyObject &operator=(const KeyObject &) = delete;

    // Bind to an existing persisted object; returns error if absent.
    Status Open(uint32_t id) {
        if (sss_key_object_get_handle(&obj_, id) != kStatus_SSS_Success)
            return SeFail(kKeyFailed, "sss_key_object_get_handle failed");
        return Ok();
    }

    // Allocate a fresh persistent object handle for a new SE object.
    Status Allocate(uint32_t id, sss_key_part_t part, sss_cipher_type_t cipher,
                    size_t byte_len) {
        sss_status_t st = sss_key_object_allocate_handle(
            &obj_, id, part, cipher, static_cast<uint32_t>(byte_len),
            kKeyObject_Mode_Persistent);
        if (st != kStatus_SSS_Success)
            return SeFail(kKeyFailed, "sss_key_object_allocate_handle failed");
        return Ok();
    }

    sss_object_t *raw() { return &obj_; }
    Connection &conn() { return conn_; }

private:
    Connection &conn_;
    sss_object_t obj_{};
    bool live_ = false;
};

} // namespace se051
