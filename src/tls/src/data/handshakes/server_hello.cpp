#include <tls/data/handshakes/server_hello.h>

namespace tls::data::handshakes {
    void ServerHello::serialize(Serializer &buffer) {
        buffer.write(version);
        buffer.write(random);
        buffer.write<uint8_t>(sessionId.size());
        buffer.write(sessionId.data(), sessionId.size());
        buffer.write(swap<CipherSuite, uint16_t>(cipherSuite));
        buffer.write(compressionMethod);
        buffer.write(extensions.data(), extensions.size());
    }

    ServerHello::ServerHello(Parser &buffer) {
        version = buffer.read<Version>();
        random = buffer.read<Random<32>>();
        sessionId.resize(buffer.read<uint8_t>());
        buffer.read(sessionId.data(), sessionId.size());
        cipherSuite = swap<CipherSuite, uint16_t>(buffer.read<CipherSuite>());
        compressionMethod = buffer.read<CompressionMethod>();

        if (buffer.sizeLeft() > 0) {
            extensions.resize(swap(buffer.read<uint16_t>()));
            buffer.read(extensions.data(), extensions.size());
        }
    }
}