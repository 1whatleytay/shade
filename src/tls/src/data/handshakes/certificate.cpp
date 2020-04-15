#include <tls/data/handshakes/certificate.h>

namespace tls::data::handshakes {
    size_t Certificate::getCertificatesSize() {
        uint32_t size = 0;

        for (const auto &certificate : certificates) {
            size += sizeof(Uint24) + certificate.size();
        }

        return size;
    }

    void Certificate::serialize(Serializer &buffer) {
        buffer.write(Uint24(getCertificatesSize()));

        for (const auto &certificate : certificates) {
            buffer.write(Uint24(certificate.size()));
            buffer.write(certificate.data(), certificate.size());
        }
    }
    
    Certificate::Certificate(Parser &buffer) {
        uint32_t certificatesSize = buffer.read<Uint24>().get(); // certificateSize

        while (buffer.sizeLeft() > 0) {
            uint32_t certificateSize = buffer.read<Uint24>().get();

            auto &certificate = certificates.emplace_back();
            certificate.resize(certificateSize);
            buffer.read(certificate.data(), certificate.size());

            if (certificate.empty())
                assert(false);
        }
    }
}