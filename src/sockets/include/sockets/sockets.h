#pragma once

#include <array>
#include <cstdint>

namespace sockets {
    using Port = uint16_t;
    using Address = std::array<uint8_t, 4>;

    class Socket {
    protected:
        int32_t socket;

        friend class ConnectionSocket;

    public:
        bool read(uint8_t *data, size_t size, ssize_t *count = nullptr);

        bool write(uint8_t *data, size_t size, ssize_t *count = nullptr);

        Socket();

        Socket(int32_t socket);

        ~Socket();
    };

    class ClientSocket : public Socket {
        Port port = 0;
        Address address = {};

    public:
        ClientSocket(Port port, Address address);
    };

    class ServerSocket : public Socket {
        Port port = 0;

    public:
        explicit ServerSocket(Port port);
    };

    class ConnectionSocket : public Socket {
        Port port = 0;
        Address address = {};

    public:
        explicit ConnectionSocket(const ServerSocket &server);
    };
}
