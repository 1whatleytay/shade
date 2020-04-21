#include <encryption/rsa.h>

namespace encryption {
    BigInt rsaModExp(const BigInt &a, const BigInt &e, const BigInt &n) {
        size_t eValue = e.toInt();

        BigInt result = BigInt::fromInt(1);

        while (eValue != 0) {
            result *= result;
            result %= n;

            if ((eValue & 1u) != 0) {
                result *= a;
                result %= n;
            }

            eValue >>= 1u;
        }

        return result % n;
    }

    BigInt rsaEncrypt(const BigInt &n, const BigInt &e, const uint8_t *data, size_t size) {
        size_t keySize = 256;

        // uwah bigint is variable size now
        if (keySize - 11 < size)
            throw std::runtime_error("RSA 2048 cannot encrypt more than 245 bytes.");

        std::vector<uint8_t> result(keySize);
        result[0] = 0x00;
        result[1] = 0x02;

        size_t paddingSize = keySize - 3 - size;

        for (uint32_t a = 0; a < paddingSize; a++) {
            uint8_t random = 0;
            while (random == 0)
                random = rand() & 0xFF;

            result[2 + a] = random;
        }
        result[2 + paddingSize] = 0x00;
        std::memcpy(&result[3 + paddingSize], data, size);

        BigInt resultInt(result.data(), result.size());
        return rsaModExp(resultInt, e, n);
    }
}
