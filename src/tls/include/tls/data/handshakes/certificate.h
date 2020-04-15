#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

namespace tls::data::handshakes {
    class Certificate {
    public:
        std::vector<std::vector<uint8_t>> certificates;

        size_t getCertificatesSize();

        void serialize(Serializer &buffer);

        Certificate() = default;
        explicit Certificate(Parser &buffer);
    };
}