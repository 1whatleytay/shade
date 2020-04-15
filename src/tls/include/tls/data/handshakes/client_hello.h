#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

namespace tls::data::handshakes {
    class ClientHello {
    public:
        Version version = { };
        Random<32> random = { };
        std::vector<uint8_t> sessionId;
        std::vector<CipherSuite> cipherSuites;
        std::vector<CompressionMethod> compressionMethods;
        std::vector<uint8_t> extensions;

        void serialize(Serializer &buffer);

        ClientHello() = default;
        explicit ClientHello(Parser &buffer);
    };
}