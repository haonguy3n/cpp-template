#pragma once

#include <se051/connection.hpp>

#include <cstddef>
#include <cstdint>

namespace se051 {

// Random bytes from the SE05x hardware TRNG. The SE session must outlive this.
class SeRandom {
public:
    explicit SeRandom(Connection &conn) : conn_(conn) {}

    // Fill `len` bytes at `out` with random data from the SE05x TRNG.
    Status Fill(uint8_t *out, size_t len);

private:
    Connection &conn_;
};

} // namespace se051
