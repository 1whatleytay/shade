#include <tls/tls.h>

namespace tls {
    void Uint24::set(uint32_t value) {
        data[2] = value & 0xFFu;
        data[1] = (value >> 8u) & 0xFFu;
        data[0] = value >> 16u;
    }

    uint32_t Uint24::get() {
        return (data[0] << 16u) | (data[1] << 8u) | data[2];
    }

    Uint24::Uint24(uint32_t value) {
        set(value);
    }
}