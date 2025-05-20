#pragma once

#include <NetworkClient.hpp>
#include <SSHPacket.hpp>
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

class SSHClient: public NetworkClient {
private:
    bool kexComplete;
    bool encryptionEnabled;
    KexAlgorithm kexAlgo;
    EncryptionAlgorithm encryptionAlgo;
    MACAlgorithm macAlgo;

    Bytes clientKexInit;
    Bytes serverKexInit;
    Bytes serverHostKey;
    Bytes sessionId;
    
    Bytes encryptionKey;
    Bytes encryptionIV;
    Bytes integrityKey;

    std::unique_ptr<crypto::AES256CBC> aes;
    
    ErrorCode performKEX();
    Bytes computeExchangeHash(const Bytes& clientPublicKey, const Bytes& serverPublicKey, const Bytes& sharedSecretKey);
    void deriveKeys(const Bytes& sharedSecret, const Bytes& exchangeHash);
    Bytes deriveKeyData(const Bytes& sharedSecret, const Bytes& exchangeHash, char purpose, size_t keySize);

    Bytes encryptBytes(const Bytes& data) const;
    Bytes decryptBytes(const Bytes& data) const;
    Bytes computeMAC(const Bytes& data, bool sending) const;
public:
    SSHClient() : 
        kexComplete(false),
        encryptionEnabled(false),
        kexAlgo(KexAlgorithm::ELLIPTIC_CURVE_DIFFIE_HELLMAN_GROUP14_SHA256),
        encryptionAlgo(EncryptionAlgorithm::AES256_CBC),
        macAlgo(MACAlgorithm::HMAC_SHA256) {}
    
    ErrorCode connectTo(const std::string& hostname, uint16_t port = SSH_DEFAULT_PORT, uint32_t timeout_ms = 5000) override;
    ErrorCode recvSSHPacket(SSHPacket& packet, unsigned int timeout_ms = 5000);
    ErrorCode sendSSHPacket(SSHPacket& packet);
};

}; // namespace ssh
