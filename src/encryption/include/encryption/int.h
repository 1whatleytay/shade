#pragma once

#include <encryption/swap.h>

#include <array>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

#include <fmt/printf.h>

namespace encryption {
    template <size_t N>
    class BigInt {
        constexpr static uint64_t halfMask = ~0ull >> 32u;

        static_assert(N > 0, "BigInt size must be at least 1.");

        static bool overflows(uint64_t a, uint64_t b) {
            return a > UINT64_MAX - b;
        }

        static bool underflows(uint64_t a, uint64_t b) {
            return b > a;
        }
    public:
        std::array<uint64_t, N> data = { };

        void division(const BigInt<N> &value, BigInt<N> &remainder, BigInt<N> &result) const {
            result = BigInt<N>();
            remainder = *this;

            size_t divSize = 0;
            for (ssize_t a = N - 1; a >= 0; a--) {
                for (ssize_t b = 63; b >= 0; b--) {
                    if ((value.data[a] & (1ull << b)) != 0) {
                        divSize = a * 64 + b;
                        break;
                    }
                }

                if (divSize != 0)
                    break;
            }

            if (divSize == 0 && value.data[0] == 0)
                throw std::runtime_error("Division by zero.");

            BigInt<N> divisor = value << (N * 64 - divSize - 1);
            for (size_t a = N * 64 - 1; a >= divSize; a--) {
                if (remainder >= divisor) {
                    remainder -= divisor;
                    size_t index = a - divSize;
                    result.data[index / 64] |= 1ull << (index % 64);
                }

                divisor >>= 1;
            }
        }

        bool compare(const BigInt<N> &value, bool greater, bool equal) const {
            for (ssize_t a = N - 1; a >= 0; a--) {
                uint64_t thisValue = data[a];
                uint64_t thatValue = value.data[a];

                if (thisValue > thatValue)
                    return greater;

                if (thisValue < thatValue)
                    return !greater;
            }

            return equal;
        }

        bool operator>(const BigInt<N> &value) const {
            return compare(value, true, false);
        }
        bool operator>=(const BigInt<N> &value) const {
            return compare(value, true, true);
        }
        bool operator<(const BigInt<N> &value) const {
            return compare(value, false, false);
        }
        bool operator<=(const BigInt<N> &value) const {
            return compare(value, false, true);
        }
        bool operator==(const BigInt<N> &value) const {
            return data == value.data;
        }
        bool operator!=(const BigInt<N> &value) const {
            return data != value.data;
        }

        BigInt<N> operator+(const BigInt<N> &value) const {
            BigInt<N> result;

            bool carry = false;
            for (size_t a = 0; a < N; a++) {
                // process 63 bits at a time, last bit is for carry
                uint64_t thisValue = data[a];
                uint64_t thatValue = value.data[a];

                uint64_t addResult = thisValue + thatValue + carry;
                carry = overflows(thisValue, thatValue) || overflows(thisValue + thatValue, carry);

                result.data[a] = addResult;
            }

            return result;
        }

        BigInt<N> operator-(const BigInt<N> &value) const {
            BigInt<N> result;

            bool carry = false;
            for (size_t a = 0; a < N; a++) {
                uint64_t thisValue = data[a];
                uint64_t thatValue = value.data[a];

                uint64_t subResult = thisValue - thatValue - carry;
                carry = underflows(thisValue, thatValue) || underflows(thisValue - thatValue, carry);

                result.data[a] = subResult;
            }

            return result;
        }

        BigInt<N> operator*(const BigInt<N> &value) const {
            BigInt<N> result;

            for (size_t a = 0; a < N; a++) {
                for (size_t b = 0; b < N; b++) {
                    if (a + b >= N - 1) // lazyyyy
                        continue;

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

                    if (overflows(current, albhValues))
                        carry += 1;
                    current += albhValues;
                    carry += albhCarry;
                    if (overflows(current, ahblValues))
                        carry += 1;
                    current += ahblValues;
                    carry += ahblCarry;

                    BigInt<N> temp;
                    temp.data[a + b] = current;
                    if (a + b + 1 >= N - 1)
                        temp.data[a + b + 1] = carry;
                    result += temp;
                }
            }

            return result;
        }

        BigInt<N> operator/(const BigInt<N> &value) const {
            BigInt<N> remainder, result;
            division(value, remainder, result);

            return result;
        }

        BigInt<N> operator%(const BigInt<N> &value) const {
            BigInt<N> remainder, result;
            division(value, remainder, result);

            return remainder;
        }

        BigInt<N> operator<<(size_t value) const {
            BigInt<N> result;

            size_t slotsShifted = value / 64;
            size_t placesShifted = value % 64;
            if (slotsShifted == 0) {
                result = *this;
            } else {
                for (size_t a = 0; a < N - slotsShifted; a++)
                    result.data[a + slotsShifted] = data[a];
            }

            size_t carryOffset = 64 - placesShifted;

            uint64_t carry = 0;
            for (size_t a = 0; a < N; a++) {
                uint64_t current = result.data[a];
                result.data[a] = (current << placesShifted) | carry;
                carry = (current >> carryOffset);
            }

            return result;
        }

        BigInt<N> operator>>(size_t value) const {
            BigInt<N> result;

            size_t slotsShifted = value / 64;
            size_t placesShifted = value % 64;
            if (slotsShifted == 0) {
                result = *this;
            } else {
                for (size_t a = slotsShifted; a < N; a++)
                    result.data[a - slotsShifted] = data[a];
            }

            size_t carryOffset = 64 - placesShifted;
            size_t carryMask = (~0ull) >> carryOffset;

            uint64_t carry = 0;
            for (ssize_t a = N - 1; a >= 0; a--) {
                uint64_t current = result.data[a];
                result.data[a] = (current >> placesShifted) | (carry << carryOffset);
                carry = current & carryMask;
            }

            return result;
        }

        BigInt<N> &operator+=(const BigInt<N> &value) {
            *this = *this + value;
            return *this;
        }

        BigInt<N> &operator-=(const BigInt<N> &value) {
            *this = *this - value;
            return *this;
        }

        BigInt<N> &operator*=(const BigInt<N> &value) {
            *this = *this * value;
            return *this;
        }

        BigInt<N> &operator/=(const BigInt<N> &value) {
            *this = *this / value;
            return *this;
        }

        BigInt<N> &operator%=(const BigInt<N> &value) {
            *this = *this % value;
            return *this;
        }

        BigInt<N> &operator<<=(size_t value) {
            *this = *this << value;
            return *this;
        }

        BigInt<N> &operator>>=(size_t value) {
            *this = *this >> value;
            return *this;
        }

        std::string toString() {
            std::stringstream stream;

            BigInt<N> temp = *this;

            const BigInt<N> zero = BigInt<N>(0);
            const BigInt<N> base = BigInt<N>(10);

            if (temp == zero)
                return "0";

            while (temp != zero) {
                BigInt<N> remainder, result;
                temp.division(base, remainder, result);
                temp = result;

                stream << remainder.data[0];
            }

            std::string text = stream.str();
            std::reverse(text.begin(), text.end());

            return text;
        }

        std::vector<uint8_t> toBinary() {
            std::vector<uint8_t> binary(data.size() * sizeof(uint64_t));
            std::memcpy(binary.data(), data.data(), data.size());

            // I want it to be big endian, too lazy to modify loop
            std::reverse(binary.begin(), binary.end());

            return binary;
        }

        uint64_t toInt() {
            return data[0];
        }

        BigInt() = default;
        explicit BigInt(std::bitset<N> data) : data(data) { }
        explicit BigInt(uint64_t value) { data[0] = value; }
        explicit BigInt(const std::string &text) {
            const BigInt<N> base(10);

            for (char a : text) {
                if (!std::isdigit(a))
                    throw std::runtime_error("Expected digits.");

                operator*=(base);
                operator+=(BigInt<N>(a - '0'));
            }
        }
        explicit BigInt(const uint8_t *intData, size_t intSize) {
            std::vector<uint8_t> tempData(intSize);
            std::memcpy(tempData.data(), intData, intSize);
            std::reverse(tempData.begin(), tempData.end());
            std::memcpy(data.data(), intData, std::min(intSize, data.size() * 8));
        }
    };
}
