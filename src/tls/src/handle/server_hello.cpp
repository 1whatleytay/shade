#include <tls/connection.h>

#include <tls/data/handshakes/server_hello.h>

namespace tls {
    void Connection::handleServerHello(Parser &buffer) {
        data::handshakes::ServerHello serverHello(buffer);

        cipherSuite = serverHello.cipherSuite;
    }
}