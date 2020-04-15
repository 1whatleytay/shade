#include <tls/connection.h>

#include <tls/data/plaintext.h>
#include <tls/data/handshake.h>
#include <tls/data/handshakes/client_hello.h>
#include <tls/data/handshakes/server_hello.h>

#include <fmt/printf.h>

namespace tls {
    void Connection::handleClientHello(Parser &buffer) {
        data::handshakes::ClientHello clientHello(buffer);

        Serializer serializer;
        data::handshakes::ServerHello serverHello;
        serverHello.version = version;
        serverHello.random.fill();
        serverHello.sessionId = { }; // illegal parameter here for some reason
        serverHello.cipherSuite = CipherSuite::RsaWithAes256CbcSha;
        serverHello.compressionMethod = CompressionMethod::None;
        serverHello.serialize(serializer);

        send(HandshakeType::ServerHello, serializer);
    }
}