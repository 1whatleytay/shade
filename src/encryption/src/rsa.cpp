#include <encryption/rsa.h>

namespace encryption {
    // https://eli.thegreenplace.net/2009/03/28/efficient-modular-exponentiation-algorithms
    RsaKey rsaModExp(RsaKey a, RsaKey e, RsaKey n) {
        constexpr size_t k = 5;
        constexpr size_t base = 1u << k;

        std::vector<RsaKey> table(base);
        table[0] = RsaKey(1);
        for (size_t b = 1; b < base; b++)
            table[b] = table[b - 1] * a % n;

        std::vector<size_t> digits;
        RsaKey remainderE = e;
        RsaKey zero(0);
        RsaKey baseInt(base);
        while (remainderE > zero) {
            RsaKey remainder, result;
            remainderE.division(baseInt, remainder, result);

            digits.push_back(remainder.toInt());
            remainderE = result;
        }

        RsaKey result(1);
        for (ssize_t b = digits.size() - 1; b >= 0; b--) {
            size_t digit = digits[b];

            for (size_t c = 0; c < k; c++) {
                result *= result;
                result %= n;
            }

            if (digit != 0) {
                result *= result * table[digit];
                result %= n;
            }
        }

        return result;
    }

    RsaKey rsaEncrypt(RsaKey e, RsaKey n, const uint8_t *data, size_t size) {
        size_t keySize = n.data.size() / 8;

        if (keySize - 11 < size)
            throw std::runtime_error("RSA 2048 cannot encrypt more than 245 bytes.");

        std::vector<uint8_t> result(keySize);
        result[0] = 0x00;
        result[1] = 0x02;

        size_t paddingSize = keySize - 3 - size;

        for (uint32_t a = 0; a < paddingSize; a++) {
            uint8_t random = 0;
            while (random == 0) {
                random = rand();
            }

            result[2 + a] = random;
        }
        result[2 + paddingSize] = 0x00;
        std::memcpy(&result[3 + paddingSize], data, size);

        RsaKey resultInt(result.data(), result.size());
        return rsaModExp(resultInt, e, n);
    }
}
