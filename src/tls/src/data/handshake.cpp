#include <tls/data/handshake.h>

namespace tls::data {
    void Handshake::serialize(tls::Serializer &buffer) {
        buffer.write(type);
        buffer.write(Uint24(size));
    }

    Handshake::Handshake(tls::Parser &buffer) {
        type = buffer.read<HandshakeType>();
        size = buffer.read<Uint24>().get();
    }
}