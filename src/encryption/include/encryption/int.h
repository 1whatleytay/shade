#pragma once

#include <encryption/swap.h>

#include <array>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

#include <fmt/printf.h>

namespace encryption {
    class BigInt {
        constexpr static uint64_t halfMask = ~0ull >> 32u;

        static bool overflows(uint64_t a, uint64_t b);

        static bool underflows(uint64_t a, uint64_t b);
    public:
        std::vector<uint64_t> data = { };

        size_t getMsbOffset() const;
        void division(const BigInt &value, BigInt &remainder, BigInt &result) const;
        bool compare(const BigInt &value, bool greater, bool equal) const;
        void simplify();
        BigInt getSimple() const;

        bool operator>(const BigInt &value) const;
        bool operator>=(const BigInt &value) const;
        bool operator<(const BigInt &value) const;
        bool operator<=(const BigInt &value) const;
        bool operator==(const BigInt &value) const;
        bool operator!=(const BigInt &value) const;

        BigInt operator+(const BigInt &value) const;
        BigInt operator-(const BigInt &value) const;
        BigInt operator*(const BigInt &value) const;
        BigInt operator/(const BigInt &value) const;
        BigInt operator%(const BigInt &value) const;
        BigInt operator~() const;
        BigInt operator<<(size_t value) const;
        BigInt operator>>(size_t value) const;

        BigInt &operator+=(const BigInt &value);
        BigInt &operator-=(const BigInt &value);
        BigInt &operator*=(const BigInt &value);
        BigInt &operator/=(const BigInt &value);
        BigInt &operator%=(const BigInt &value);
        BigInt &operator<<=(size_t value);
        BigInt &operator>>=(size_t value);

        uint64_t toInt() const;
        std::string toString() const;
        std::vector<uint8_t> toBinary() const;

        static BigInt fromInt(uint64_t value);
        static BigInt fromString(const std::string &text);

        BigInt() = default;
        explicit BigInt(size_t size);
        explicit BigInt(const uint8_t *intData, size_t intSize);
    };
}
