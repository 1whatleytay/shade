#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

namespace tls::data {
    class Alert {
    public:
        AlertLevel level;
        AlertDescription description;

        constexpr static size_t defaultSize = 2;

        void serialize(Serializer &buffer);

        Alert() = default;
        explicit Alert(Parser &buffer);
    };
}