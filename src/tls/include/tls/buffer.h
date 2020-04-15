#pragma once

#include <vector>
#include <cstdint>
#include <cstring>

namespace tls {
    class Parser {
        const uint8_t *data = nullptr;
        size_t index = 0;
        size_t size = 0;

    public:
        template <typename T>
        T read() {
            T value;

            std::memcpy(&value, data + index, sizeof(T));

            index += sizeof(T);

            if (index > size)
                throw std::runtime_error("Parser read too much.");

            return value;
        }

        template <typename T>
        void read(T *value, size_t count = 1) {
            std::memcpy(value, data + index, count * sizeof(T));

            index += count * sizeof(T);

            if (index > size)
                throw std::runtime_error("Parser read too much.");
        }

        size_t sizeLeft();

        explicit Parser(const uint8_t *data, size_t size);
        ~Parser();
    };

    class Serializer {
        std::vector<uint8_t> data = { };

    public:
        template <typename T>
        void write(T value) {
            auto *valueData = reinterpret_cast<const uint8_t *>(&value);

            data.insert(data.end(), valueData, valueData + sizeof(T));
        }

        template <typename T>
        void write(const T *value, size_t count = 1) {
            auto *valueData = reinterpret_cast<const uint8_t *>(value);

            data.insert(data.end(), valueData, valueData + count * sizeof(T));
        }

        void append(const Serializer &serializer);

        uint8_t *getData();
        size_t getSize();
    };
}