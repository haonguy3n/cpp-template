// Phase 0 build spike: prove the NXP SSS headers compile and the middleware
// links against se051's mbedTLS 3.6.6. This is a placeholder TU; the real
// session/keys/provisioning wrappers replace it in later phases.

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
}

namespace se051 {

// Returns the size of the SSS session struct -- enough to force the headers and
// a symbol from the middleware to be referenced and linked.
unsigned long Se05xProbe() {
    return static_cast<unsigned long>(sizeof(sss_session_t));
}

} // namespace se051
