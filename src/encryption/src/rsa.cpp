#include <encryption/rsa.h>

namespace encryption {
    RsaKey rsaModExp(RsaKey a, RsaKey e, RsaKey n) {
        size_t eValue = e.toInt();

        RsaKey value(1);
        RsaKey result(a);

        while (eValue != 0) {
            if ((eValue & 1u) != 0) {
                value *= result;
                value %= n;
            }

            result *= result;
            result %= n;
            eValue >>= 1u;
        }

        return result % n;
    }

    RsaKey rsaEncrypt(RsaKey n, RsaKey e, const uint8_t *data, size_t size) {
        size_t keySize = 256;

        if (keySize - 11 < size)
            throw std::runtime_error("RSA 2048 cannot encrypt more than 245 bytes.");

        std::vector<uint8_t> result(keySize);
        result[0] = 0x00;
        result[1] = 0x02;

        size_t paddingSize = keySize - 3 - size;

        for (uint32_t a = 0; a < paddingSize; a++) {
            uint8_t random = 0;
            while (random == 0) {
                random = 47;
            }

            result[2 + a] = random;
        }
        result[2 + paddingSize] = 0x00;
        std::memcpy(&result[3 + paddingSize], data, size);

        RsaKey resultInt(result.data(), result.size());
        return rsaModExp(resultInt, e, n);
    }
}
