#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

namespace tls::data::handshakes {
    class ClientKeyExchangeRsa {
    public:
        Version version;
        Random<46> random;

        void serialize(Serializer &buffer);

        ClientKeyExchangeRsa() = default;
        explicit ClientKeyExchangeRsa(Parser &buffer);
    };
}