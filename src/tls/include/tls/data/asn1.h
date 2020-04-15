#pragma once

#include <tls/tls.h>
#include <tls/buffer.h>

#include <any>
#include <string>

namespace tls::data {
    class Asn1 {
    public:
        enum class TagClassification {
            Universal = 0,
            Application = 1,
            ContextSpecific = 2,
            Private = 3,
        };

        enum class TagType {
            Unknown = 0,
            Integer = 2,
            BitString = 3,
            OctetString = 4,
            Null = 5,
            ObjectId = 6,
            Sequence = 16,
            Set = 17,
            Printable = 19,
            T61String = 20,
            IA5String = 22,
            UtcTime = 23,
        };

        uint8_t tag = 0;
        TagType type = TagType::Unknown;
        TagClassification classification = TagClassification::Universal;
        bool hasChildren = false;
        uint32_t length = 0;
        std::vector<Asn1> children;

        std::vector<uint8_t> data;

        uint64_t getInteger();
        std::string getString();

        void serialize(Serializer &buffer);

        explicit Asn1(Parser &buffer);
    };
}