#include <tls/connection.h>

#include <tls/data/handshakes/client_hello.h>

namespace tls {
    void Connection::handleInitialize() {
        Serializer serializer;
        data::handshakes::ClientHello clientHello;
        clientHello.version = version;
        clientHello.random.fill();
        clientHello.sessionId = { };
        clientHello.cipherSuites = {
            CipherSuite::RsaWithAes256CbcSha
        };
        clientHello.compressionMethods = {
            CompressionMethod::None
        };
        clientHello.serialize(serializer);

        send(HandshakeType::ClientHello, serializer);
    }
}