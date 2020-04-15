#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

namespace tls::data::handshakes {
    class ServerHello {
    public:
        Version version = { };
        Random<32> random = { };
        std::vector<uint8_t> sessionId;
        CipherSuite cipherSuite = CipherSuite::NoCipher;
        CompressionMethod compressionMethod = CompressionMethod::None;
        std::vector<uint8_t> extensions;

        void serialize(Serializer &buffer);

        ServerHello() = default;
        explicit ServerHello(Parser &buffer);
    };
}