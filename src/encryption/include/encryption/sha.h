#include <array>

namespace encryption {
    std::array<uint32_t, 8> sha256Hash(uint8_t *data, size_t size);
}