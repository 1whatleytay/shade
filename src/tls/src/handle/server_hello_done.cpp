#include <tls/connection.h>

#include <tls/data/handshakes/client_key_exchange_rsa.h>

namespace tls {
    void Connection::handleServerHelloDone(Parser &buffer) {
        data::handshakes::ClientKeyExchangeRsa key;
        key.version = version;
        key.random.fill();
    }
}