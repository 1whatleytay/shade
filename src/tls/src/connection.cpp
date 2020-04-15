#include <tls/connection.h>

#include <tls/names.h>

#include <tls/data/alert.h>
#include <tls/data/plaintext.h>

#include <fmt/printf.h>
#include <tls/data/handshake.h>

namespace tls {
    void Connection::send(ContentType contentType, Serializer &serializer) {
        Serializer plaintextSerializer;
        data::Plaintext plaintext;
        plaintext.type = contentType;
        plaintext.version = version;
        plaintext.length = serializer.getSize();
        plaintext.serialize(plaintextSerializer);
        plaintextSerializer.append(serializer);

        write(plaintextSerializer.getData(), plaintextSerializer.getSize());
    }
    void Connection::send(HandshakeType handshakeType, Serializer &serializer) {
        Serializer handshakeSerializer;
        data::Handshake handshake;
        handshake.type = handshakeType;
        handshake.size = serializer.getSize();
        handshake.serialize(handshakeSerializer);
        handshakeSerializer.append(serializer);

        send(ContentType::Handshake, handshakeSerializer);
    }

    void Connection::handleHandshake(Parser &buffer) {
        data::Handshake handshake(buffer);

        switch (handshake.type) {
            case HandshakeType::ClientHello:
                handleClientHello(buffer);
                break;
            case HandshakeType::ServerHello:
                handleServerHello(buffer);
                break;
            case HandshakeType::Certificate:
                handleCertificate(buffer);
                break;
            case HandshakeType::ServerHelloDone:
                handleServerHelloDone(buffer);
                break;
            default:
                assert(false);
                break;
        }
    }

    void Connection::handleAlert(Parser &buffer) {
        data::Alert alert(buffer);

        fmt::print("Received Alert: [{}] {}\n",
            getAlertLevelName(alert.level), getAlertDescriptionName(alert.description));
    }

    void Connection::run() {
        fmt::print("Starting connection.\n");

        if (type == Type::Client)
            handleInitialize();

        while (exec) {
            std::array<uint8_t, data::Plaintext::defaultSize> buffer = { };
            if (!read(buffer.data(), buffer.size()))
                assert(false);
            Parser plaintextBuffer(buffer.data(), buffer.size());
            data::Plaintext plaintext(plaintextBuffer);

            std::vector<uint8_t> fragment(plaintext.length);
            if (!read(fragment.data(), fragment.size()))
                assert(false);
            Parser fragmentBuffer(fragment.data(), fragment.size());

            switch (plaintext.type) {
                case ContentType::Handshake:
                    handleHandshake(fragmentBuffer);
                    break;
                case ContentType::Alert:
                    handleAlert(fragmentBuffer);
                    break;
                default:
                    assert(false); // unimplemented
                    break;
            }
        }
    }

    Connection::Connection(Type type, IoCallback read, IoCallback write)
        : type(type), read(std::move(read)), write(std::move(write)) { }
}