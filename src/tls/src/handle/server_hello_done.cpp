#include <tls/connection.h>

#include <tls/data/handshakes/client_key_exchange_rsa.h>

#include <encryption/rsa.h>

namespace tls {
    void Connection::handleServerHelloDone(Parser &buffer) {
        data::handshakes::ClientKeyExchangeRsa key;
        key.version = version;
        key.random.fill();

        Serializer serializer;
        key.serialize(serializer);

        assert(publicKeyN.toInt() != 0);
        assert(publicKeyE.toInt() != 0);

        std::vector<uint8_t> result
            = encryption::rsaEncrypt(publicKeyE, publicKeyN, serializer.getData(), serializer.getSize()).toBinary();

        Serializer output;
        output.write(result.data(), result.size());

        send(HandshakeType::ClientKeyExchange, output);

        Serializer spec;
        spec.write<uint8_t>(1); // change cipher spec
        send(ContentType::ChangeCipherSpec, spec);
    }
}