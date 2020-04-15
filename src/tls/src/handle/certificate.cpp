#include <tls/connection.h>

#include <tls/data/asn1.h>
#include <tls/data/handshakes/certificate.h>

#include <fmt/printf.h>

#include <sstream>

namespace tls {
    std::string binString(const std::vector<uint8_t> &data) {
        std::stringstream result;

        result << "0x";

        for (uint8_t a : data) {
            result << fmt::format("{:0>2X}", a);
        }

        return result.str();
    }

    void Connection::handleCertificate(Parser &buffer) {
        data::handshakes::Certificate certificate(buffer);

        for (const auto &a : certificate.certificates) {
            Parser parser(a.data(), a.size());

            fmt::print("Certificate:\n");

            data::Asn1 root(parser);

            data::Asn1 info = root.children[0];
            size_t certVersion = info.children[0].children[0].getInteger();
            std::vector<uint8_t> certSerial = info.children[1].data;
            std::vector<uint8_t> algorithm = info.children[2].children[0].data;
            std::vector<uint8_t> countryCode = info.children[3].children[0].children[0].children[0].data;
            std::string country = info.children[3].children[0].children[0].children[1].getString();
            std::vector<uint8_t> unitCode = info.children[3].children[1].children[0].children[0].data;
            std::string unit = info.children[3].children[1].children[0].children[1].getString();
            std::string startDate = info.children[4].children[0].getString();
            std::string endDate = info.children[4].children[1].getString();
//            std::vector<uint8_t> countryCode2 = info.children[5].children[0].children[0].children[0].data;
//            std::string country2 = info.children[5].children[0].children[0].children[1].getString();
            std::vector<uint8_t> nameCode = info.children[5].children[1].children[0].children[0].data;
            std::string name = info.children[5].children[1].children[0].children[1].getString();
            std::vector<uint8_t> keyId = info.children[6].children[0].children[0].data;
            std::vector<uint8_t> publicKey = info.children[6].children[1].data;
            Parser publicKeyParser(publicKey.data(), publicKey.size());
            data::Asn1 publicKeyInfo(publicKeyParser);
            std::vector<uint8_t> n = publicKeyInfo.children[0].data;
            uint64_t e = publicKeyInfo.children[1].getInteger();

            fmt::print("\tVersion: {}\n", certVersion);
            fmt::print("\tSerial: {}\n", binString(certSerial));
            fmt::print("\tAlgorithm: {}\n", binString(algorithm));
            fmt::print("\tCountry: {} ({})\n", country, binString(countryCode));
//            fmt::print("\tCountry2: {} ({})\n", country2, binString(countryCode2));
            fmt::print("\tUnit: {} ({})\n", unit, binString(unitCode));
            fmt::print("\tValid: {} -> {}\n", startDate, endDate);
            fmt::print("\tName: {} ({})\n", name, binString(nameCode));
            fmt::print("\tPublic Key: ({})\n", binString(keyId));
            fmt::print("\t\tn: {}\n", binString(std::vector<uint8_t>(n.begin() + 1, n.end())));
            fmt::print("\t\te: {}\n", e);

            publicKeyN = std::vector<uint8_t>(n.begin() + 1, n.end());
            publicKeyE = e;
        }
    }
}