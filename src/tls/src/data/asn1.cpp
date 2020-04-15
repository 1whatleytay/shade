#include <tls/data/asn1.h>

#include <climits>

namespace tls::data {
    uint64_t Asn1::getInteger() {
        size_t result = 0;

        for (uint8_t a : data) {
            result <<= 8u;
            result |= a;
        }

        return result;
    }

    std::string Asn1::getString() {
        return std::string(data.begin(), data.end());
    }

    // serializing is unintuitive with length, later maybe use Serializer::getSize()
    void Asn1::serialize(Serializer &buffer) {
        uint8_t tag = 0;
        tag |= static_cast<uint8_t>(classification);
        tag <<= 1u;
        tag |= hasChildren;
        tag <<= 5u;
        tag |= static_cast<uint8_t>(type);
        buffer.write(tag);

        if (length > 127) {
            uint32_t bytesRequired = 1;
            if (length > 255)
                bytesRequired++;
            if (length > 65535)
                bytesRequired++;
            if (length > 16777215)
                bytesRequired++;

            buffer.write<uint8_t>(0b10000000u | bytesRequired);

            for (uint32_t a = 0; a < bytesRequired; a++) {
                buffer.write<uint8_t>(length >> ((bytesRequired - a - 1) * 8));
            }
        } else {
            buffer.write<uint8_t>(length);
        }

        switch (type) {
            default:
                assert(false); // unimplemented
                break;
        }
    }

    Asn1::Asn1(Parser &buffer) {
        tag = buffer.read<uint8_t>();

        type = static_cast<TagType>(tag & 0b00011111u);
        hasChildren = (tag & 0b00100000u) != 0;
        classification = static_cast<TagClassification>((tag & 0b110000000u) >> 6u);

        auto firstLength = buffer.read<uint8_t>();

        if ((firstLength & 0b10000000u) != 0) {
            uint32_t byteCount = firstLength & 0b01111111u;

            for (uint32_t a = 0; a < byteCount; a++) {
                length <<= 8u;
                length |= buffer.read<uint8_t>();
            }
        } else {
            length = firstLength & 0b01111111u;
        }

        if (hasChildren) {
            uint32_t startBytes = buffer.sizeLeft();
            while (startBytes - buffer.sizeLeft() < length) {
                children.emplace_back(buffer);
            }
        } else {
            uint32_t toRead = length;

            if (type == TagType::BitString) {
                auto padding = buffer.read<uint8_t>();
                assert(padding == 0);
                toRead--;
            }

            data.resize(toRead);
            buffer.read(data.data(), data.size());
        }
    }
}