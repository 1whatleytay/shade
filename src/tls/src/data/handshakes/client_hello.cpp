#include <tls/data/handshakes/client_hello.h>

namespace tls::data::handshakes {
    void ClientHello::serialize(Serializer &buffer) {
        buffer.write(version);
        buffer.write(random);
        buffer.write<uint8_t>(sessionId.size());
        buffer.write(sessionId.data(), sessionId.size());
        buffer.write(swap<uint16_t>(cipherSuites.size() * sizeof(CipherSuite)));
        for (const CipherSuite &suite : cipherSuites)
            buffer.write(swap<CipherSuite, uint16_t>(suite));
        buffer.write<uint8_t>(compressionMethods.size());
        buffer.write(compressionMethods.data(), compressionMethods.size());
        buffer.write(extensions.data(), extensions.size());
    }

    ClientHello::ClientHello(Parser &buffer) {
        version = buffer.read<Version>();
        random = buffer.read<Random<32>>();
        sessionId.resize(buffer.read<uint8_t>());
        buffer.read(sessionId.data(), sessionId.size());
        cipherSuites.resize(swap(buffer.read<uint16_t>()) / sizeof(CipherSuite));
        buffer.read(cipherSuites.data(), cipherSuites.size());
        for (CipherSuite &suite : cipherSuites)
            suite = swap<CipherSuite, uint16_t>(suite);
        compressionMethods.resize(buffer.read<uint8_t>());
        buffer.read(compressionMethods.data(), compressionMethods.size());

        if (buffer.sizeLeft() > 0) {
            extensions.resize(swap(buffer.read<uint16_t>()));
            buffer.read(extensions.data(), extensions.size());
        }
    }
}