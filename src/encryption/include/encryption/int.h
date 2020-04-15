#pragma once

#include <bitset>
#include <string>
#include <vector>
#include <sstream>

namespace encryption {
    template <size_t N>
    class BigInt {
        constexpr static uint64_t highMask = (1ull << 63ull);
        constexpr static uint64_t noHighMask = ~highMask;
    public:
        std::bitset<N> data;

        void division(const BigInt<N> &value, BigInt<N> &remainder, BigInt<N> &result) const {
            result = BigInt<N>();
            remainder = *this;

            size_t divSize;
            for (divSize = N - 1; !value.data[divSize]; divSize--) {
                if (divSize == 0)
                    throw std::runtime_error("Division by zero.");
            }

            bool carry = false;
            for (size_t a = N - 1; a >= divSize; a--) {
                std::bitset<N> shiftedDiv = value.data << (a - divSize);

                if (carry) {
                    remainder -= BigInt<N>(shiftedDiv);
                    result.data[a - divSize] = true;
                    carry = false;
                }

                if (remainder.data[a]) {
                    if ((remainder >= BigInt(shiftedDiv))) {
                        remainder -= BigInt<N>(shiftedDiv);
                        result.data[a - divSize] = true;
                    } else {
                        carry = true;
                    }
                }
            }
        }

        bool compare(const BigInt<N> &value, bool greater, bool equal) const {
            std::bitset<N> full(~0ull);

            for (ssize_t a = (N / 64 * 64); a >= 0; a -= 64) {
                uint64_t thisValue = ((data >> a) & full).to_ullong();
                uint64_t thatValue = ((value.data >> a) & full).to_ullong();

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

            const std::bitset<N> noHighMaskBits(noHighMask);

            bool carry = false;
            for (size_t a = 0; a < N; a += 63) {
                // process 63 bits at a time, last bit is for carry
                uint64_t thisValue = ((data >> a) & noHighMaskBits).to_ullong();
                uint64_t thatValue = ((value.data >> a) & noHighMaskBits).to_ullong();

                uint64_t addResult = thisValue + thatValue + carry;
                carry = (addResult & highMask) != 0;

                result.data |= std::bitset<N>(addResult & noHighMask) << a;
            }

            return result;
        }

        BigInt<N> &operator+=(const BigInt<N> &value) {
            *this = *this + value;
            return *this;
        }

        BigInt<N> operator-(const BigInt<N> &value) const {
            BigInt<N> result;

            const std::bitset<N> noHighMaskBits(noHighMask);

            bool carry = false;
            for (size_t a = 0; a < N; a += 63) {
                int64_t thisValue = ((data >> a) & noHighMaskBits).to_ullong();
                int64_t thatValue = ((value.data >> a) & noHighMaskBits).to_ullong();

                int64_t subResult = thisValue - thatValue - carry;

                carry = subResult < 0;
                if (carry)
                    subResult += highMask;

                result.data |= std::bitset<N>(static_cast<uint64_t>(subResult) & noHighMask) << a;
            }

            return result;
        }

        BigInt<N> &operator-=(const BigInt<N> &value) {
            *this = *this - value;
            return *this;
        }

        BigInt<N> operator*(const BigInt<N> &value) const {
            BigInt<N> result;

            for (size_t a = 0; a < N; a++) {
                if (value.data[a]) {
                    result += BigInt<N>(data << a);
                }
            }

            return result;
        }

        BigInt<N> &operator*=(const BigInt<N> &value) {
            *this = *this * value;
            return *this;
        }

        BigInt<N> operator/(const BigInt<N> &value) const {
            BigInt<N> remainder, result;
            division(value, remainder, result);

            return result;
        }

        BigInt<N> &operator/=(const BigInt<N> &value) {
            *this = *this / value;
            return *this;
        }

        BigInt<N> operator%(const BigInt<N> &value) const {
            BigInt<N> remainder, result;
            division(value, remainder, result);

            return remainder;
        }

        BigInt<N> &operator%=(const BigInt<N> &value) {
            *this = *this % value;
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
                temp.div(base, remainder, result);
                temp = result;

                stream << remainder.data.to_ullong();
            }

            std::string text = stream.str();
            std::reverse(text.begin(), text.end());

            return text;
        }

        std::vector<uint8_t> toBinary() {
            std::vector<uint8_t> binary;

            for (size_t a = 0; a < N; a += 8) {
                binary.push_back(((data >> a) & std::bitset<N>(0xFFu)).to_ullong());
            }

            // I want it to be big endian, too lazy to modify loop
            std::reverse(binary.begin(), binary.end());

            return binary;
        }

        uint64_t toInt() {
            return (data & std::bitset<N>(~0ull)).to_ullong();
        }

        BigInt() = default;
        explicit BigInt(std::bitset<N> data) : data(data) { }
        explicit BigInt(uint64_t value) : data(std::bitset<N>(value)) { }
        explicit BigInt(const std::string &text) {
            const BigInt<N> base(10);

            for (char a : text) {
                if (!std::isdigit(a))
                    throw std::runtime_error("Expected digits.");

                operator*=(base);
                operator+=(BigInt<N>(a - '0'));
            }
        }
        explicit BigInt(const uint8_t *intData, size_t intSize) { // big endian in
            for (size_t a = 0; a < intSize; a++) {
                data <<= 8u;
                data |= intData[a];
            }
        }
    };
}
