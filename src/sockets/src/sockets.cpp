#include <sockets/sockets.h>

#include <unistd.h>
#include <arpa/inet.h>

namespace sockets {
    bool Socket::read(uint8_t *data, size_t size, ssize_t *count) {
        ssize_t bytesRead = ::recv(socket, data, size, MSG_WAITALL);

        // we shouldn't use throw here
        if (bytesRead < 0)
            return false;
        if (bytesRead == 0)
            return false;

        if (count) {
            *count = bytesRead;
        }

        return true;
    }

    bool Socket::write(uint8_t *data, size_t size, ssize_t *count) {
        ssize_t bytesSent = ::send(socket, data, size, 0);

        // we shouldn't use throw here
        if (bytesSent < 0)
            return false;
        if (bytesSent == 0)
            return false;

        if (count) {
            *count = bytesSent;
        }

        return true;
    }

    Socket::Socket() : Socket(::socket(AF_INET, SOCK_STREAM, 0)) {}

    Socket::Socket(int32_t socket) : socket(socket) {
        if (socket == -1)
            throw std::runtime_error("Cannot create socket.");
    }

    Socket::~Socket() {
        close(socket);
    }

    ClientSocket::ClientSocket(Port port, Address address) : port(port), address(address) {
        sockaddr_in addressIn = {};
        std::memset(&addressIn, 0, sizeof(addressIn));
        addressIn.sin_family = AF_INET;
        addressIn.sin_port = htons(port);
        std::memcpy(&addressIn.sin_addr.s_addr, address.data(), address.size());

        if (::connect(socket, reinterpret_cast<sockaddr *>(&addressIn), sizeof(addressIn)) == -1)
            throw std::runtime_error("Socket connection failed.");
    }

    ServerSocket::ServerSocket(Port port) : port(port) {
        sockaddr_in addressIn = {};
        std::memset(&addressIn, 0, sizeof(addressIn));
        addressIn.sin_family = AF_INET;
        addressIn.sin_port = htons(port);
        addressIn.sin_addr.s_addr = INADDR_ANY;

        if (::bind(socket, reinterpret_cast<sockaddr *>(&addressIn), sizeof(addressIn)) == -1)
            throw std::runtime_error("Socket binding failed.");

        if (::listen(socket, 5) == -1)
            throw std::runtime_error("Socket listening failed.");
    }

    ConnectionSocket::ConnectionSocket(const ServerSocket &server) {
        sockaddr_in addressIn = {};
        uint32_t size;

        socket = ::accept(server.socket, reinterpret_cast<sockaddr *>(&addressIn), &size);

        if (socket == -1)
            throw std::runtime_error("Socket connection failed.");

        port = ntohs(addressIn.sin_port);
        std::memcpy(address.data(), &addressIn.sin_addr.s_addr, address.size());
    }
}
