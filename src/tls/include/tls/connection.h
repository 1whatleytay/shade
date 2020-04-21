#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

#include <encryption/int.h>

#include <functional>

namespace tls {
    using ReadIoCallback = std::function<bool(uint8_t *data, uint32_t size)>;
    using WriteIoCallback = std::function<bool(const uint8_t *data, uint32_t size)>;

    enum class Type {
        Server,
        Client
    };

    class Connection {
        Type type;
        ReadIoCallback read;
        WriteIoCallback write;

        Version version = { 3, 3 };

        encryption::BigInt publicKeyN;
        encryption::BigInt publicKeyE;

        void send(ContentType type, const Serializer &serializer);
        void send(HandshakeType type, const Serializer &serializer);

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

        Connection(Type type, ReadIoCallback read, WriteIoCallback write);
    };
}