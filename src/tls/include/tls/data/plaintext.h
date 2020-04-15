#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

namespace tls::data {
    class Plaintext {
    public:
        ContentType type = ContentType::Invalid;
        Version version;
        uint16_t length = 0;

        constexpr static size_t defaultSize = 5;

        void serialize(Serializer &buffer);

        Plaintext() = default;
        explicit Plaintext(Parser &buffer);
    };
}