#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

namespace tls::data {
    class Handshake {
    public:
        HandshakeType type = HandshakeType::HelloRequest;
        uint32_t size = 0;

        constexpr static size_t defaultSize = 4;

        void serialize(Serializer &buffer);

        Handshake() = default;
        explicit Handshake(Parser &buffer);
    };
}