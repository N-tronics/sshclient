#pragma once

#include <SSHPacket.hpp>
#include <NetUtils.hpp>
#include <Crypto.hpp>
#include <TypeDefs.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace ssh {

constexpr uint32_t SSH_DEFAULT_PORT = 22;
// SSH protocol version
const std::string SSH_PROTOCOL_VERSION = "SSH-2.0-CustomSSH_0.1";

// SSH message types (based on RFC 4253)
enum class MsgType : Byte {
    // Transport layer protocol
    DISCONNECT = 1,
    IGNORE = 2,
    UNIMPLEMENTED = 3,
    DEBUG = 4,
    SERVICE_REQUEST = 5,
    SERVICE_ACCEPT = 6,
    KEXINIT = 20,
    NEWKEYS = 21,
    
    // Key exchange specific messages
    KEX_DH_INIT = 30,
    KEX_DH_REPLY = 31,
    
    // User authentication messages
    USERAUTH_REQUEST = 50,
    USERAUTH_FAILURE = 51,
    USERAUTH_SUCCESS = 52,
    USERAUTH_BANNER = 53,
    
    // Connection protocol messages
    GLOBAL_REQUEST = 80,
    REQUEST_SUCCESS = 81,
    REQUEST_FAILURE = 82,
    CHANNEL_OPEN = 90,
    CHANNEL_OPEN_CONFIRMATION = 91,
    CHANNEL_OPEN_FAILURE = 92,
    CHANNEL_WINDOW_ADJUST = 93,
    CHANNEL_DATA = 94,
    CHANNEL_EOF = 96,
    CHANNEL_CLOSE = 97,
    CHANNEL_REQUEST = 98,
    CHANNEL_SUCCESS = 99,
    CHANNEL_FAILURE = 100
};

// SSH key exchange algorithms
enum class KexAlgorithm {
    ELLIPTIC_CURVE_DIFFIE_HELLMAN_GROUP14_SHA256
};

// SSH encryption algorithms
enum class EncryptionAlgorithm {
    AES256_CBC
};

// SSH MAC algorithms
enum class MACAlgorithm {
    HMAC_SHA256
};

class SSHUtils : public NetUtils {
public:
    KexAlgorithm kexAlgo;
    EncryptionAlgorithm encryptionAlgo;
    MACAlgorithm macAlgo;

    Bytes encryptionKey;
    Bytes encryptionIV;
    Bytes partnerRSAKey;
    Bytes integrityKey;
    Bytes sessionId;

    std::unique_ptr<crypto::AES256CBC> aes;

    SSHUtils() {}
    SSHUtils(const NetUtils& utils);
    
    Bytes computeExchangeHash(
        const Bytes& clientProtocol,
        const Bytes& serverProtocol,
        const Bytes& clientKexInit,
        const Bytes& serverKexInit,
        const Bytes& clientPublicKey,
        const Bytes& serverPublicKey,
        const Bytes& sharedSecretKey
    );
    void deriveKeys(const Bytes& sharedSecret, const Bytes& exchangeHash, std::string id);
    Bytes deriveKeyData(const Bytes& sharedSecret, const Bytes& exchangeHash, char purpose, size_t keySize);

    Bytes encryptBytes(const Bytes& data) const;
    Bytes decryptBytes(const Bytes& data) const;
    Bytes computeMAC(const Bytes& data, bool sending) const;
    
    ErrorCode recvSSHPacket(SSHPacket& packet, uint32_t timeout_ms = 5000) const;
    ErrorCode sendSSHPacket(SSHPacket& packet) const;
};

} // namespace ssh
