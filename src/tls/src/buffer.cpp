#include <tls/buffer.h>

namespace tls {
    size_t Parser::sizeLeft() {
        return size - index;
    }

    Parser::Parser(const uint8_t *data, size_t size) : data(data), size(size) { }

    Parser::~Parser() {
        if (size != index)
            assert(false);
    }

    void Serializer::append(const Serializer &serializer) {
        data.insert(data.end(), serializer.data.begin(), serializer.data.end());
    }

    uint8_t * Serializer::getData() {
        return data.data();
    }

    size_t Serializer::getSize() {
        return data.size();
    }
}