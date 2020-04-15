#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

#include <functional>

namespace tls {
    using IoCallback = std::function<bool(uint8_t *data, uint32_t size)>;

    enum class Type {
        Server,
        Client
    };

    class Connection {
        Type type;
        IoCallback read;
        IoCallback write;

        Version version = { 3, 3 };
        CipherSuite cipherSuite = CipherSuite::NoCipher;
        std::vector<uint8_t> publicKeyN = { };
        uint64_t publicKeyE = 0;

        void send(ContentType type, Serializer &serializer);
        void send(HandshakeType type, Serializer &serializer);

        void handleInitialize();
        void handleClientHello(Parser &buffer);
        void handleServerHello(Parser &buffer);
        void handleCertificate(Parser &buffer);
        void handleServerHelloDone(Parser &buffer);

        void handleHandshake(Parser &buffer);
        void handleAlert(Parser &buffer);
    public:
        volatile bool exec = true;

        void run();

        Connection(Type type, IoCallback read, IoCallback write);
    };
}