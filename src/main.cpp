#include <sockets/sockets.h>
#include <tls/connection.h>

int main() {
    sockets::ClientSocket socket(443, { 216, 58, 211, 110 });

    tls::Connection connection(tls::Type::Client,
        [&socket](uint8_t *data, uint32_t size) { return socket.read(data, size); },
        [&socket](uint8_t *data, uint32_t size) { return socket.write(data, size); });

    connection.run();

    return 0;
}
