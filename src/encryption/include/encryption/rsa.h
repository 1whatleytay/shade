#pragma once

#include <encryption/int.h>

#include <vector>

namespace encryption {
    BigInt rsaEncrypt(const BigInt &e, const BigInt &n, const uint8_t *data, size_t size);
}
