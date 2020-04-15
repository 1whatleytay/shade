#pragma once

#include <encryption/swap.h>

#include <array>
#include <cstdint>

namespace tls {
    using encryption::swap;

    enum class ContentType : uint8_t {
        Invalid = 0,
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23,
    };

    enum class HandshakeType : uint8_t {
        HelloRequest = 0,
        ClientHello = 1,
        ServerHello = 2,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20,
    };

    enum class AlertLevel : uint8_t {
        Warning = 1,
        Fatal = 2,
    };

    enum class AlertDescription : uint8_t {
        CloseNotification = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        DecryptionFailed = 21,
        RecordOverflow = 22,
        DecompressionFailure = 30,
        HandshakeFailure = 40,
        NoCertificate = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExportRestriction = 60,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        UserCanceled = 90,
        NoRenegotiation = 100,
        UnsupportedExtension = 110,
    };

    enum class CipherSuite : uint16_t {
        NoCipher = 0x0000,
        RsaWithMD5 = 0x0001,
        RsaWithSha = 0x0002,
        RsaWithSha256 = 0x003B,
        RsaWithRc4128MD5 = 0x0004,
        RsaWithRc4128Sha = 0x0005,
        RsaWith3desEdeCbcSha = 0x000A,
        RsaWithAes128CbcSha = 0x002F,
        RsaWithAes256CbcSha = 0x0035,
        RsaWithAes128CbcSha256 = 0x003C,
        RsaWithAes256CbcSha256 = 0x003D,
        EcdheEcdsaWithAes128GcmSha256 = 0xC02B,
        EcdheRsaWithAes128GcmSha256 = 0xC02F,
        EcdheEcdsaWithAes256GcmSha384 = 0xC02C,
        EcdheRsaWithAes256GcmSha384 = 0xC030,
        PskWithAes256Ccm8 = 0xCCA9,
        PskWithAes128Ccm8 = 0xCCA8,
        EcdheRsaWithAes128CbcSha = 0xC013,
        EcdheRsaWithAes256CbcSha = 0xC014,
        RsaWithAes128GcmSha256 = 0x009C,
        RsaWithAes256GcmSha384 = 0x009D,
    };

    enum class ExtensionType : uint16_t {
        ServerName = 0x0000,
        MaxFragmentLength = 0x0001,
        StatusRequest = 0x0005,
        SupportedGroups = 0x000A,
        SignatureAlgorithms = 0x000D,
        UseSrtp = 0x000E,
        Heartbeat = 0x000F,
        ProtocolNames = 0x0010,
        SignedCertificateTimestamp = 0x0012,
        ClientCertificateType = 0x0013,
        ServerCertificateType = 0x0014,
        Padding = 0x0015,
        PreSharedKey = 0x0029,
        EarlyData = 0x002A,
        SupportedVersions = 0x002B,
        Cookie = 0x002C,
        PskKeyExchange_Modes = 0x002D,
        CertificateAuthorities = 0x002F,
        OidFilters = 0x0030,
        PostHandshakeAuth = 0x0031,
        SignatureAlgorithmsCert = 0x0032,
        KeyShare = 0x0033,
    };

    enum class SupportedGroup : uint16_t {
        Secp256r1 = 0x0017,
        Secp384r1 = 0x0018,
        Secp521r1 = 0x0019,
        X25519 = 0x001D,
        X448 = 0x001E,
        Ffdhe2048 = 0x0100,
        Ffdhe3072 = 0x0101,
        Ffdhe4096 = 0x0102,
        Ffdhe6144 = 0x0103,
        Ffdhe8192 = 0x0104,
    };

    enum class SignatureAlgorithm : uint16_t {
        RsaPkcs1Sha256 = 0x0401,
        RsaPkcs1Sha384 = 0x0501,
        RsaPkcs1Sha512 = 0x0601,
        EcdsaSecp256r1Sha256 = 0x0403,
        EcdsaSecp384r1Sha384 = 0x0503,
        EcdsaSecp521r1Sha512 = 0x0603,
        RsaPssRsaeSha256 = 0x0804,
        RsaPssRsaeSha384 = 0x0805,
        RsaPssRsaeSha512 = 0x0806,
        Ed25519 = 0x0807,
        Ed448 = 0x0808,
        RsaPssPssSha256 = 0x0809,
        RsaPssPssSha384 = 0x080a,
        RsaPssPssSha512 = 0x080b,
        RsaPkcs1Sha1 = 0x0201,
        EcdsaSha1 = 0x0203,
    };

    enum class CompressionMethod : uint8_t {
        None = 0,
    };

    class Version {
    public:
        uint8_t major = 0;
        uint8_t minor = 0;
    };

    template <size_t S>
    class Random {
    public:
        std::array<uint8_t, S> data = { };

        void fill() {
            for (unsigned char &a : data) {
                a = rand() & 0xFFu; // TODO: change this out for something in <random> at least
            }
        }
    };

    class Uint24 {
    public:
        std::array<uint8_t, 3> data = { };

        void set(uint32_t value);
        uint32_t get();

        Uint24() = default;
        explicit Uint24(uint32_t value);
    };
}
