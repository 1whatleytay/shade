#include <tls/data/handshakes/client_key_exchange_rsa.h>

namespace tls::data::handshakes {
    void ClientKeyExchangeRsa::serialize(Serializer &buffer) {
        buffer.write(version);
        buffer.write(random.data.data(), random.data.size());
    }

    ClientKeyExchangeRsa::ClientKeyExchangeRsa(Parser &buffer) {
        version = buffer.read<Version>();
        buffer.read(random.data.data(), random.data.size());
    }
}