#include <se051/random.hpp>
#include <se051/log/log.hpp>

extern "C" {
#include <fsl_sss_api.h>
}

namespace se051 {

Status SeRandom::Fill(uint8_t *out, size_t len) {
    if (len == 0)
        return Ok();

    sss_rng_context_t rng{};
    sss_status_t st = sss_rng_context_init(&rng, conn_.session());
    if (st != kStatus_SSS_Success) {
        SE051_LOG_ERROR("se: sss_rng_context_init failed (0x%04x)", static_cast<unsigned>(st));
        return SeFail(kRngFailed, "sss_rng_context_init failed");
    }

    st = sss_rng_get_random(&rng, out, len);
    sss_rng_context_free(&rng);

    if (st != kStatus_SSS_Success) {
        SE051_LOG_ERROR("se: sss_rng_get_random failed (0x%04x)", static_cast<unsigned>(st));
        return SeFail(kRngFailed, "sss_rng_get_random failed");
    }

    return Ok();
}

} // namespace se051
