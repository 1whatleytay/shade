#pragma once

#include <encryption/int.h>

#include <vector>

namespace encryption {
    using RsaKey = BigInt<2048>;

    RsaKey rsaEncrypt(RsaKey e, RsaKey n, const uint8_t *data, size_t size);
}
