#pragma once

#include <tls/tls.h>

namespace tls {
    const char *getContentTypeName(ContentType value);
    const char *getHandshakeTypeName(HandshakeType value);
    const char *getAlertLevelName(AlertLevel value);
    const char *getAlertDescriptionName(AlertDescription value);
    const char *getCipherSuiteName(CipherSuite value);
    const char *getCompressionMethodName(CompressionMethod value);
    const char *getExtensionTypeName(ExtensionType value);
    const char *getSupportedGroupName(SupportedGroup value);
    const char *getSignatureAlgorithmName(SignatureAlgorithm value);
}