#include <tls/names.h>

namespace tls {
    const char *getContentTypeName(ContentType value) {
        switch (value) {
            case ContentType::ChangeCipherSpec: return "ChangeCipherSpec";
            case ContentType::Alert: return "Alert";
            case ContentType::Handshake: return "Handshake";
            case ContentType::ApplicationData: return "ApplicationData";
            default: return "Unknown";
        }
    }

    const char *getHandshakeTypeName(HandshakeType value) {
        switch (value) {
            case HandshakeType::HelloRequest: return "HelloRequest";
            case HandshakeType::ClientHello: return "ClientHello";
            case HandshakeType::ServerHello: return "ServerHello";
            case HandshakeType::Certificate: return "Certificate";
            case HandshakeType::ServerKeyExchange: return "ServerKeyExchange";
            case HandshakeType::CertificateRequest: return "CertificateRequest";
            case HandshakeType::ServerHelloDone: return "ServerHelloDone";
            case HandshakeType::CertificateVerify: return "CertificateVerify";
            case HandshakeType::ClientKeyExchange: return "ClientKeyExchange";
            case HandshakeType::Finished: return "Finished";
            default: return "Unknown";
        }
    }

    const char *getAlertLevelName(AlertLevel value) {
        switch (value) {
            case AlertLevel::Warning: return "Warning";
            case AlertLevel::Fatal: return "Fatal";
            default: return "Unknown";
        }
    }

    const char *getAlertDescriptionName(AlertDescription value) {
        switch (value) {
            case AlertDescription::CloseNotification: return "CloseNotification";
            case AlertDescription::UnexpectedMessage: return "UnexpectedMessage";
            case AlertDescription::BadRecordMac: return "BadRecordMac";
            case AlertDescription::DecryptionFailed: return "DecryptionFailed";
            case AlertDescription::RecordOverflow: return "RecordOverflow";
            case AlertDescription::DecompressionFailure: return "DecompressionFailure";
            case AlertDescription::HandshakeFailure: return "HandshakeFailure";
            case AlertDescription::NoCertificate: return "NoCertificate";
            case AlertDescription::BadCertificate: return "BadCertificate";
            case AlertDescription::UnsupportedCertificate: return "UnsupportedCertificate";
            case AlertDescription::CertificateRevoked: return "CertificateRevoked";
            case AlertDescription::CertificateExpired: return "CertificateExpired";
            case AlertDescription::CertificateUnknown: return "CertificateUnknown";
            case AlertDescription::IllegalParameter: return "IllegalParameter";
            case AlertDescription::UnknownCa: return "UnknownCa";
            case AlertDescription::AccessDenied: return "AccessDenied";
            case AlertDescription::DecodeError: return "DecodeError";
            case AlertDescription::DecryptError: return "DecryptError";
            case AlertDescription::ExportRestriction: return "ExportRestriction";
            case AlertDescription::ProtocolVersion: return "ProtocolVersion";
            case AlertDescription::InsufficientSecurity: return "InsufficientSecurity";
            case AlertDescription::InternalError: return "InternalError";
            case AlertDescription::UserCanceled: return "UserCanceled";
            case AlertDescription::NoRenegotiation: return "NoRenegotiation";
            case AlertDescription::UnsupportedExtension: return "UnsupportedExtension";
            default: return "Unknown";
        }
    }

    const char *getCipherSuiteName(CipherSuite value) {
        switch (value) {
            case CipherSuite::NoCipher: return "NoCipher";
            case CipherSuite::RsaWithMD5: return "RsaWithMD5";
            case CipherSuite::RsaWithSha: return "RsaWithSha";
            case CipherSuite::RsaWithSha256: return "RsaWithSha256";
            case CipherSuite::RsaWithRc4128MD5: return "RsaWithRc4128MD5";
            case CipherSuite::RsaWithRc4128Sha: return "RsaWithRc4128Sha";
            case CipherSuite::RsaWith3desEdeCbcSha: return "RsaWith3desEdeCbcSha";
            case CipherSuite::RsaWithAes128CbcSha: return "RsaWithAes128CbcSha";
            case CipherSuite::RsaWithAes256CbcSha: return "RsaWithAes256CbcSha";
            case CipherSuite::RsaWithAes128CbcSha256: return "RsaWithAes128CbcSha256";
            case CipherSuite::RsaWithAes256CbcSha256: return "RsaWithAes256CbcSha256";
            case CipherSuite::EcdheEcdsaWithAes128GcmSha256: return "EcdheEcdsaWithAes128GcmSha256";
            case CipherSuite::EcdheRsaWithAes128GcmSha256: return "EcdheRsaWithAes128GcmSha256";
            case CipherSuite::EcdheEcdsaWithAes256GcmSha384: return "EcdheEcdsaWithAes256GcmSha384";
            case CipherSuite::EcdheRsaWithAes256GcmSha384: return "EcdheRsaWithAes256GcmSha384";
            case CipherSuite::PskWithAes256Ccm8: return "PskWithAes256Ccm8";
            case CipherSuite::PskWithAes128Ccm8: return "PskWithAes128Ccm8";
            case CipherSuite::EcdheRsaWithAes128CbcSha: return "EcdheRsaWithAes128CbcSha";
            case CipherSuite::EcdheRsaWithAes256CbcSha: return "EcdheRsaWithAes256CbcSha";
            case CipherSuite::RsaWithAes128GcmSha256: return "RsaWithAes128GcmSha256";
            case CipherSuite::RsaWithAes256GcmSha384: return "RsaWithAes256GcmSha384";
            default: return "Unknown";
        }
    }

    const char *getCompressionMethodName(CompressionMethod value) {
        switch (value) {
            case CompressionMethod::None: return "None";
            default: return "Unknown";
        }
    }

    const char *getExtensionTypeName(ExtensionType value) {
        switch (value) {
            case ExtensionType::ServerName: return "ServerName";
            case ExtensionType::MaxFragmentLength: return "MaxFragmentLength";
            case ExtensionType::StatusRequest: return "StatusRequest";
            case ExtensionType::SupportedGroups: return "SupportedGroups";
            case ExtensionType::SignatureAlgorithms: return "SignatureAlgorithms";
            case ExtensionType::UseSrtp: return "UseSrtp";
            case ExtensionType::Heartbeat: return "Heartbeat";
            case ExtensionType::ProtocolNames: return "ProtocolNames";
            case ExtensionType::SignedCertificateTimestamp: return "SignedCertificateTimestamp";
            case ExtensionType::ClientCertificateType: return "ClientCertificateType";
            case ExtensionType::ServerCertificateType: return "ServerCertificateType";
            case ExtensionType::Padding: return "Padding";
            case ExtensionType::PreSharedKey: return "PreSharedKey";
            case ExtensionType::EarlyData: return "EarlyData";
            case ExtensionType::SupportedVersions: return "SupportedVersions";
            case ExtensionType::Cookie: return "Cookie";
            case ExtensionType::PskKeyExchange_Modes: return "PskKeyExchange_Modes";
            case ExtensionType::CertificateAuthorities: return "CertificateAuthorities";
            case ExtensionType::OidFilters: return "OidFilters";
            case ExtensionType::PostHandshakeAuth: return "PostHandshakeAuth";
            case ExtensionType::SignatureAlgorithmsCert: return "SignatureAlgorithmsCert";
            case ExtensionType::KeyShare: return "KeyShare";
            default: return "Unknown";
        }
    }

    const char *getSupportedGroupName(SupportedGroup value) {
        switch (value) {
            case SupportedGroup::Secp256r1: return "Secp256r1";
            case SupportedGroup::Secp384r1: return "Secp384r1";
            case SupportedGroup::Secp521r1: return "Secp521r1";
            case SupportedGroup::X25519: return "X25519";
            case SupportedGroup::X448: return "X448";
            case SupportedGroup::Ffdhe2048: return "Ffdhe2048";
            case SupportedGroup::Ffdhe3072: return "Ffdhe3072";
            case SupportedGroup::Ffdhe4096: return "Ffdhe4096";
            case SupportedGroup::Ffdhe6144: return "Ffdhe6144";
            case SupportedGroup::Ffdhe8192: return "Ffdhe8192";
            default: return "Unknown";
        }
    }

    const char *getSignatureAlgorithmName(SignatureAlgorithm value) {
        switch (value) {
            case SignatureAlgorithm::RsaPkcs1Sha256: return "RsaPkcs1Sha256";
            case SignatureAlgorithm::RsaPkcs1Sha384: return "RsaPkcs1Sha384";
            case SignatureAlgorithm::RsaPkcs1Sha512: return "RsaPkcs1Sha512";
            case SignatureAlgorithm::EcdsaSecp256r1Sha256: return "EcdsaSecp256r1Sha256";
            case SignatureAlgorithm::EcdsaSecp384r1Sha384: return "EcdsaSecp384r1Sha384";
            case SignatureAlgorithm::EcdsaSecp521r1Sha512: return "EcdsaSecp521r1Sha512";
            case SignatureAlgorithm::RsaPssRsaeSha256: return "RsaPssRsaeSha256";
            case SignatureAlgorithm::RsaPssRsaeSha384: return "RsaPssRsaeSha384";
            case SignatureAlgorithm::RsaPssRsaeSha512: return "RsaPssRsaeSha512";
            case SignatureAlgorithm::Ed25519: return "Ed25519";
            case SignatureAlgorithm::Ed448: return "Ed448";
            case SignatureAlgorithm::RsaPssPssSha256: return "RsaPssPssSha256";
            case SignatureAlgorithm::RsaPssPssSha384: return "RsaPssPssSha384";
            case SignatureAlgorithm::RsaPssPssSha512: return "RsaPssPssSha512";
            case SignatureAlgorithm::RsaPkcs1Sha1: return "RsaPkcs1Sha1";
            case SignatureAlgorithm::EcdsaSha1: return "EcdsaSha1";
            default: return "Unknown";
        }
    }
}