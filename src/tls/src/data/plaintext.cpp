#include <tls/data/plaintext.h>

namespace tls::data {
    void Plaintext::serialize(Serializer &buffer) {
        buffer.write(type);
        buffer.write(version);
        buffer.write(swap(length));
    }

    Plaintext::Plaintext(Parser &buffer) {
        type = buffer.read<ContentType>();
        version = buffer.read<Version>();
        length = swap(buffer.read<uint16_t>());
    }
}