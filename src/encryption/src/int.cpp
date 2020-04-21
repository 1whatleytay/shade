#include <encryption/int.h>

#include <array>

namespace encryption {
    bool BigInt::overflows(uint64_t a, uint64_t b) {
        return a > UINT64_MAX - b;
    }

    bool BigInt::underflows(uint64_t a, uint64_t b) {
        return b > a;
    }

    void BigInt::simplify() {
        ssize_t index;
        for (index = data.size() - 1; index >= 0; index--) {
            if (data[index] != 0)
                break;
        }

        data.resize(index + 1);
    }

    BigInt BigInt::getSimple() const {
        BigInt result = *this;
        result.simplify();
        return result;
    }

    size_t BigInt::getMsbOffset() const {
        size_t offset = 0;
        for (ssize_t a = data.size() - 1; a >= 0; a--) {
            for (ssize_t b = 63; b >= 0; b--) {
                if ((data[a] & (1ull << b)) != 0) {
                    offset = a * 64 + b;
                    break;
                }
            }

            if (offset != 0)
                break;
        }

        return offset;
    }

    void BigInt::division(const BigInt &value, BigInt &remainder, BigInt &result) const {
        result = BigInt(); // zero
        remainder = *this;

        ssize_t divSize = value.getMsbOffset();

        if (divSize == 0 && (value.data.empty() || value.data[0] == 0))
            throw std::runtime_error("Division by zero.");

        ssize_t thisOffset = getMsbOffset();
        if (thisOffset < divSize)
            return;

        BigInt divisor = value << (thisOffset - divSize);
        for (ssize_t a = thisOffset; a >= divSize; a--) {
            if (remainder >= divisor) {
                remainder -= divisor;
                size_t index = a - divSize;
                size_t element = index / 64;
                size_t bit = index % 64;
                if (result.data.size() <= element)
                    result.data.resize(element + 1);
                result.data[element] |= 1ull << bit;
            }

            divisor >>= 1;
        }

        remainder.simplify();
        result.simplify();
    }

    bool BigInt::compare(const BigInt &value, bool greater, bool equal) const {
        BigInt thisSimple = getSimple();
        BigInt thatSimple = value.getSimple();

        size_t thisSize = thisSimple.data.size();
        size_t thatSize = thatSimple.data.size();

        if (thisSize > thatSize)
            return greater;
        if (thatSize > thisSize)
            return !greater;

        size_t sizeToCheck = std::min(data.size(), value.data.size());

        for (ssize_t a = sizeToCheck - 1; a >= 0; a--) {
            uint64_t thisValue = data[a];
            uint64_t thatValue = value.data[a];

            if (thisValue > thatValue)
                return greater;

            if (thisValue < thatValue)
                return !greater;
        }

        return equal;
    }

    bool BigInt::operator>(const BigInt &value) const {
        return compare(value, true, false);
    }

    bool BigInt::operator>=(const BigInt &value) const {
        return compare(value, true, true);
    }

    bool BigInt::operator<(const BigInt &value) const {
        return compare(value, false, false);
    }

    bool BigInt::operator<=(const BigInt &value) const {
        return compare(value, false, true);
    }

    bool BigInt::operator==(const BigInt &value) const {
        BigInt simpleThis = getSimple();
        BigInt simpleThat = value.getSimple();

        if (simpleThis.data.size() != simpleThat.data.size())
            return false;

        return std::memcmp(simpleThis.data.data(), simpleThat.data.data(),
            simpleThis.data.size() * sizeof(uint64_t)) == 0;
    }

    bool BigInt::operator!=(const BigInt &value) const {
        return !operator==(value);
    }

    BigInt &BigInt::operator+=(const BigInt &value) {
        BigInt simpleValue = value.getSimple();

        if (data.size() < simpleValue.data.size())
            data.resize(simpleValue.data.size());

        bool carry = false;
        for (size_t a = 0; a < data.size(); a++) {
            uint64_t thisValue = data[a];
            uint64_t thatValue = 0;
            if (value.data.size() > a)
                thatValue = value.data[a];

            data[a] = thisValue + thatValue + carry;

            carry = overflows(thisValue, thatValue) || overflows(thisValue + thatValue, carry);
        }

        if (carry)
            data.push_back(1);

        return *this;
    }

    BigInt &BigInt::operator-=(const BigInt &value) {
        BigInt simpleValue = value.getSimple();

        if (data.size() < simpleValue.data.size())
            data.resize(simpleValue.data.size());

        bool carry = false;
        for (size_t a = 0; a < data.size(); a++) {
            uint64_t thisValue = data[a];
            uint64_t thatValue = 0;
            if (value.data.size() > a)
                thatValue = value.data[a];

            data[a] = thisValue - thatValue - carry;

            carry = underflows(thisValue, thatValue) || underflows(thisValue - thatValue, carry);
        }

        // no carry overflow behaviour, i suppose set sign bit or something??

        return *this;
    }

    BigInt &BigInt::operator*=(const BigInt &value) {
        *this = *this * value;
        return *this;
    }

    BigInt &BigInt::operator/=(const BigInt &value) {
        *this = *this / value;
        return *this;
    }

    BigInt &BigInt::operator%=(const BigInt &value) {
        *this = *this % value;
        return *this;
    }

    BigInt &BigInt::operator<<=(size_t value) {
        size_t slotsShifted = value / 64;
        size_t placesShifted = value % 64;

        if (slotsShifted != 0) {
            size_t originalSize = data.size();
            data.resize(data.size() + slotsShifted);
            for (size_t a = 0; a < originalSize; a++) {
                size_t index = data.size() - 1 - a;
                data[index] = data[index - slotsShifted];
            }
            std::memset(data.data(), 0, slotsShifted * sizeof(uint64_t));
        }

        if (placesShifted != 0) {
            size_t carryOffset = 64 - placesShifted;

            uint64_t carry = 0;
            for (uint64_t a = 0; a < data.size(); a++) {
                uint64_t current = data[a];
                data[a] = (current << placesShifted) | carry;
                carry = current >> carryOffset;
            }

            // don't discard carry
            if (carry != 0)
                data.push_back(carry);
        }

        return *this;
    }

    BigInt &BigInt::operator>>=(size_t value) {
        size_t slotsShifted = value / 64;
        size_t placesShifted = value % 64;

        if (slotsShifted != 0) {
            for (size_t a = slotsShifted; a < data.size(); a++)
                data[a - slotsShifted] = data[a];
            data.resize(data.size() - slotsShifted);
        }

        if (placesShifted != 0) {
            size_t carryOffset = 64 - placesShifted;
            size_t carryMask = (~0ull) >> carryOffset;

            uint64_t carry = 0;
            for (ssize_t a = data.size() - 1; a >= 0; a--) {
                uint64_t current = data[a];
                data[a] = (current >> placesShifted) | (carry << carryOffset);
                carry = current & carryMask;
            }

            // discard carry
        }

        return *this;
    }

    BigInt BigInt::operator+(const BigInt &value) const {
        BigInt result = *this;
        result += value;
        return result;
    }

    BigInt BigInt::operator-(const BigInt &value) const {
        BigInt result = *this;
        result -= value;
        return result;
    }

    BigInt BigInt::operator*(const BigInt &value) const {
        BigInt temp;
        BigInt result;

        for (size_t a = 0; a < data.size(); a++) {
            for (size_t b = 0; b < value.data.size(); b++) {
                /*
                 * [AB] * [CD] = B*D + C*D< + B*D< + A*C<<
                 */

                uint64_t valA = data[a];
                uint64_t valB = value.data[b];

                if (valA == 0)
                    continue;
                if (valB == 0)
                    continue;

                uint64_t aLo = valA & halfMask;
                uint64_t aHi = valA >> 32u;
                uint64_t bLo = valB & halfMask;
                uint64_t bHi = valB >> 32u;

                uint64_t albl = aLo * bLo;
                uint64_t albh = aLo * bHi;
                uint64_t ahbl = aHi * bLo;
                uint64_t ahbh = aHi * bHi;

                uint64_t albhValues = (albh & halfMask) << 32u;
                uint64_t ahblValues = (ahbl & halfMask) << 32u;

                uint64_t albhCarry = albh >> 32u;
                uint64_t ahblCarry = ahbl >> 32u;

                // this is fine it won't overflow I hope
                uint64_t current = albl; // B*D
                uint64_t carry = ahbh;

                if (overflows(current, albhValues)) {
                    assert(!overflows(carry, 1));
                    carry += 1;
                }
                current += albhValues;
                assert(!overflows(carry, albhCarry));
                carry += albhCarry;
                if (overflows(current, ahblValues)) {
                    assert(!overflows(carry, 1));
                    carry += 1;
                }
                current += ahblValues;
                assert(!overflows(carry, ahblCarry));
                carry += ahblCarry;

                // reuse memory if possible
                if (temp.data.size() < a + b + 2)
                    temp.data.resize(a + b + 2);
                temp.data[a + b] = current;
                temp.data[a + b + 1] = carry;
                result += temp;

                // clean up instead of memset :P
                temp.data[a + b] = 0;
                temp.data[a + b + 1] = 0;
            }
        }

        return result;
    }

    BigInt BigInt::operator/(const BigInt &value) const {
        BigInt remainder, result;
        division(value, remainder, result);

        return result;
    }

    BigInt BigInt::operator%(const BigInt &value) const {
        BigInt remainder, result;
        division(value, remainder, result);

        return remainder;
    }

    BigInt BigInt::operator~() const {
        BigInt result(data.size());

        for (size_t a = 0; a < data.size(); a++)
            result.data[a] = ~data[a];

        return result;
    }

    BigInt BigInt::operator<<(size_t value) const {
        BigInt result = *this;
        result <<= value;
        return result;
    }

    BigInt BigInt::operator>>(size_t value) const {
        BigInt result = *this;
        result >>= value;
        return result;
    }

    uint64_t BigInt::toInt() const {
        if (data.empty())
            return 0;

        return data[0];
    }

    std::string BigInt::toString() const {
        std::stringstream stream;

        BigInt temp = *this;

        const BigInt zero = BigInt::fromInt(0);
        const BigInt base = BigInt::fromInt(10);

        if (temp == zero)
            return "0";

        while (temp != zero) {
            BigInt remainder, result;
            temp.division(base, remainder, result);
            temp = result;

            uint64_t number = 0;
            if (!remainder.data.empty())
                number = remainder.data[0];

            stream << number;
        }

        std::string text = stream.str();
        std::reverse(text.begin(), text.end());

        return text;
    }

    std::vector<uint8_t> BigInt::toBinary() const {
        std::vector<uint8_t> binary(data.size() * sizeof(uint64_t));
        std::memcpy(binary.data(), data.data(), data.size() * sizeof(uint64_t));

        // I want it to be big endian, too lazy to modify loop
        std::reverse(binary.begin(), binary.end());

        return binary;
    }

    BigInt BigInt::fromInt(uint64_t value) {
        BigInt result(1);
        result.data[0] = value;
        return result;
    }

    BigInt BigInt::fromString(const std::string &text) {
        BigInt base = BigInt::fromInt(10);

        BigInt result;

        for (char a : text) {
            if (!std::isdigit(a))
                throw std::runtime_error("Expected digits.");

            result *= base;
            result += BigInt::fromInt(a - '0');
        }

        return result;
    }

    BigInt::BigInt(size_t size) : data(size) { }

    BigInt::BigInt(const uint8_t *intData, size_t intSize) : data((intSize + 7) / 8) {
        std::vector<uint8_t> tempData(intSize);
        std::memcpy(tempData.data(), intData, intSize);
        std::reverse(tempData.begin(), tempData.end());

        std::memcpy(data.data(), tempData.data(), intSize);
    }
}