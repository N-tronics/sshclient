#include <SSHClient.hpp>
#include <SSHPacket.hpp>
#include <Crypto.hpp>
#include <Types.hpp>
#include <MathFns.hpp>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <cstring>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

namespace ssh {

ErrorCode SSHClient::performKEX() {
    std::cout << "Starting key exchange with server..." << std::endl;

    SSHPacket kexInitPacket(static_cast<Byte>(MsgType::KEXINIT));
    Bytes cookie = crypto::Random::generateBytes(16);

    Bytes kexInitPayload = cookie;
    std::string kexAlgos = "diffie-hellman-group14-sha256";
    kexInitPayload.insert(kexInitPayload.end(), kexAlgos.begin(), kexAlgos.end());
        
    // Add server host key algorithms (ssh-rsa)
    std::string hostKeyAlgos = "ssh-rsa";
    kexInitPayload.insert(kexInitPayload.end(), hostKeyAlgos.begin(), hostKeyAlgos.end());
    
    // Add encryption algorithms (aes256-cbc)
    std::string encAlgos = "aes256-cbc";
    kexInitPayload.insert(kexInitPayload.end(), encAlgos.begin(), encAlgos.end());
    
    // Add MAC algorithms (hmac-sha256)
    std::string macAlgos = "hmac-sha256";
    kexInitPayload.insert(kexInitPayload.end(), macAlgos.begin(), macAlgos.end());
    
    // Add compression algorithms (none)
    std::string compAlgos = "none";
    kexInitPayload.insert(kexInitPayload.end(), compAlgos.begin(), compAlgos.end());
    
    // Add languages (empty)
    kexInitPayload.push_back(0);
    
    // Add first_kex_packet_follows (false)
    kexInitPayload.push_back(0);

    // Add reserved (0)
    for (int i = 0; i < 4; i++)
        kexInitPayload.push_back(0);

    kexInitPacket.setPayload(kexInitPayload);
    
    // Send packet
    std::cout << "Sending KEXINIT..." << std::endl;
    ErrorCode result = NetworkClient::sendTCPPacket(kexInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send KEXINIT: " << static_cast<int>(result) << std::endl;
        return result;
    }

    std::cout << "Waiting for server's KEXINIT" << std::endl;
    SSHPacket serverKexInitPacket;
    result = NetworkClient::recvTCPPacket(serverKexInitPacket, SSH_MAX_PACKET_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to recv KEXINIT: " << static_cast<int>(result) << std::endl;
    }

    if (serverKexInitPacket.getMsgType() != static_cast<Byte>(MsgType::KEXINIT)) {
        std::cout << "Invalid message type received: " << static_cast<int>(serverKexInitPacket.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Received server KEXINIT" << std::endl;
    
    serverKexInit = serverKexInitPacket.serialize();
    clientKexInit = kexInitPacket.serialize();

    std::cout << "Generating ECDH Key pair..." << std::endl;
    // ECDH
    std::unique_ptr<crypto::ecdh::ECDH> ecdh = std::make_unique<crypto::ecdh::ECDH>("brainpoolP256r1");
    
    SSHPacket dhInitPacket(static_cast<Byte>(MsgType::KEX_DH_INIT));
    Bytes dhInitPayload;
    crypto::ecdh::Point publicKeyPoint = ecdh->getPublicKeyPoint();
    Bytes publicKeyX = numToBytes(publicKeyPoint.x, 32), publicKeyY = numToBytes(publicKeyPoint.y, 32);
    dhInitPayload.insert(dhInitPayload.end(), publicKeyX.begin(), publicKeyX.end());
    dhInitPayload.insert(dhInitPayload.end(), publicKeyY.begin(), publicKeyY.end());
    dhInitPacket.setPayload(dhInitPayload);
    
    std::cout << "Sending KEX_DH_INIT..." << std::endl;
    result = NetworkClient::sendTCPPacket(dhInitPacket);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send KEX_DH_INIT: " << static_cast<int>(result) << std::endl;
        return result;
    }

    std::cout << "Waiting for server's KEX_DH_REPLY" << std::endl;
    SSHPacket dhReplyPacket;
    result = NetworkClient::recvTCPPacket(dhReplyPacket, SSH_MAX_PACKET_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to recv KEX_DH_INIT: " << static_cast<int>(result) << std::endl;
    }

    if (dhReplyPacket.getMsgType() != static_cast<Byte>(MsgType::KEX_DH_REPLY)) {
        std::cout << "Invalid message type received: " << static_cast<int>(dhReplyPacket.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Received server KEX_DH_REPLY" << std::endl;

    const Bytes& replyPayload = dhReplyPacket.getPayload();
    
    //size_t offset = 0;  // TODO: SET OFFSET
    //serverHostKey.assign(replyPayload.begin() + offset, replyPayload.end());
    //Bytes serverPublicKey(replyPayload.begin(), replyPayload.end());
    // RSA server public key
    crypto::ecdh::Point serverPublicKeyPoint;
    Bytes serverExchangeHash;

    std::cout << "Computing shared secret..." << std::endl;
    crypto::ecdh::Point sharedSecretPoint = ecdh->getPrivateKey() * serverPublicKeyPoint;
    num_t sharedSecret = sharedSecretPoint.x;

    std::cout << "Computing exchange hash..." << std::endl;
    Bytes exchangeHash = computeExchangeHash(numToBytes(ecdh->getPublicKey()), numToBytes(serverPublicKeyPoint.x), numToBytes(sharedSecret));
    
    // Verify exchange hashes
    if (!std::equal(exchangeHash.begin(), exchangeHash.end(), serverExchangeHash.begin(), serverExchangeHash.end())) {
        std::cout << "Exchange hash invalid!" << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Exchange hash verified" << std::endl;

    if (sessionId.empty())
        sessionId = exchangeHash;

    std::cout << "Deriving encryption keys..." << std::endl;
    deriveKeys(numToBytes(sharedSecret), exchangeHash);

    std::cout << "Sending NEWKEYS..." << std::endl;
    result = NetworkClient::sendTCPPacket(SSHPacket(static_cast<Byte>(MsgType::NEWKEYS)));
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send NEWKEYS" << std::endl;
        NetworkClient::disconnect();
        return result;
    }

    std::cout << "Waiting for server's NEWKEYS..." << std::endl;
    SSHPacket serverNewKeysPacket;
    result = NetworkClient::recvTCPPacket(serverNewKeysPacket, SSH_MAX_PACKET_SIZE);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to receive NEWKEYS: " << static_cast<int>(result) << std::endl;
        NetworkClient::disconnect();
        return result;
    }
    if (serverNewKeysPacket.getMsgType() != static_cast<Byte>(MsgType::NEWKEYS)) {
        std::cout << "Invalid Message Type received: " << static_cast<Byte>(serverNewKeysPacket.getMsgType()) << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::PROTOCOL_ERROR;
    }

    std::cout << "Received server NEWKEYS" << std::endl;
    std::cout << "Enabling encryption..." << std::endl;
    kexComplete = true;
    encryptionEnabled = true;
    
    std::cout << "Key Exchange completed successfully!" << std::endl;
    return ErrorCode::SUCCESS;
}

Bytes SSHClient::computeExchangeHash(const Bytes& clientPublicKey, const Bytes& serverPublicKey, const Bytes& sharedSecretKey) {
    Bytes inputs;
    inputs.insert(inputs.end(), clientProtocol.begin(), clientProtocol.end());
    inputs.insert(inputs.end(), serverProtocol.begin(), serverProtocol.end());
    inputs.insert(inputs.end(), clientKexInit.begin(), clientKexInit.end());
    inputs.insert(inputs.end(), serverKexInit.begin(), serverKexInit.end());
    inputs.insert(inputs.end(), serverHostKey.begin(), serverHostKey.end());
    inputs.insert(inputs.end(), clientPublicKey.begin(), clientPublicKey.end());
    inputs.insert(inputs.end(), serverPublicKey.begin(), serverPublicKey.end());
    inputs.insert(inputs.end(), sharedSecretKey.begin(), sharedSecretKey.end());

    return crypto::SHA256::compute(inputs);
}

void SSHClient::deriveKeys(const Bytes& sharedSecret, const Bytes& exchangeHash) {
    std::cout << "Deriving Keys from shared secret and exchange hash..." << std::endl;

    encryptionKey = deriveKeyData(sharedSecret, exchangeHash, 'C', crypto::AES256::KEY_SIZE);
    encryptionIV = deriveKeyData(sharedSecret, exchangeHash, 'A', crypto::AES256::BLOCK_SIZE);
    integrityKey = deriveKeyData(sharedSecret, exchangeHash, 'E', crypto::HMACSHA256::DIGEST_SIZE);

    try {
        aes = std::make_unique<crypto::AES256CBC>(encryptionKey, encryptionIV);
        std::cout << "AES Intialized successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "AES Initialization failed: " << e.what() << std::endl;
        throw;
    }
}

Bytes SSHClient::deriveKeyData(const Bytes& sharedSecret, const Bytes& exchangeHash, char purpose, size_t keySize) {
    // K1 = HASH(K || H || X || sessin_id)
    // K = sharedSecret, H = exchangeHash, X = purpse byte
    Bytes input;
    input.insert(input.end(), sharedSecret.begin(), sharedSecret.end());
    input.insert(input.end(), exchangeHash.begin(), exchangeHash.end());
    input.push_back(static_cast<Byte>(purpose));
    input.insert(input.end(), sessionId.begin(), sessionId.end());

    Bytes result = crypto::SHA256::compute(input);
    while (result.size() < keySize) {
        input.clear();
        input.insert(input.end(), sharedSecret.begin(), sharedSecret.end());
        input.insert(input.end(), exchangeHash.begin(), exchangeHash.end());
        input.insert(input.end(), result.begin(), result.end());

        Bytes additionalData = crypto::SHA256::compute(input);
        result.insert(result.end(), additionalData.begin(), additionalData.end());
    }
    result.resize(keySize);
    return result;
}

Bytes SSHClient::encryptBytes(const Bytes& data) const {
    if (!aes)
        throw std::runtime_error("Encryption not initialized");
    
    try {
        return aes->encrypt(data);
    } catch (const std::exception& e) {
        std::cout << "Encryption failed: " << e.what() << std::endl;
        throw;
    }
}

Bytes SSHClient::decryptBytes(const Bytes& data) const {
    if (!aes)
        throw std::runtime_error("Encryption not initialized");
    
    return aes->decrypt(data);
}

Bytes SSHClient::computeMAC(const Bytes& data, bool sending) const {
    if (integrityKey.empty()) {
        throw std::runtime_error("MAC key not initialized");
    }
    
    // Compute sequence number as a 4-byte big-endian integer
    static uint32_t sendSeqNum = 0;
    static uint32_t recvSeqNum = 0;
    
    uint32_t seqNum = sending ? sendSeqNum++ : recvSeqNum++;
    Bytes seqNumBytes(4);
    seqNumBytes[0] = (seqNum >> 24) & 0xFF;
    seqNumBytes[1] = (seqNum >> 16) & 0xFF;
    seqNumBytes[2] = (seqNum >> 8) & 0xFF;
    seqNumBytes[3] = seqNum & 0xFF;
    
    std::cout << "Computing MAC with sequence number: " << seqNum << std::endl;
    
    // Concatenate sequence number and packet data
    Bytes macData = seqNumBytes;
    macData.insert(macData.end(), data.begin(), data.end());
    
    // Compute HMAC
    try {
        Bytes mac = crypto::HMACSHA256::compute(integrityKey, macData);
        std::cout << "MAC computed successfully, size: " << mac.size() << " bytes" << std::endl;
        return mac;
    } catch (const std::exception& e) {
        std::cout << "MAC computation failed: " << e.what() << std::endl;
        throw;
    }
}

ErrorCode SSHClient::connectTo(const std::string& _hostName, uint16_t _port, unsigned int timeout_ms) {
    ErrorCode result = NetworkClient::connectTo(_hostName, _port, timeout_ms);
    if (result != ErrorCode::SUCCESS)
        return result;

    result = performKEX();
    if (result != ErrorCode::SUCCESS) {
        NetworkClient::disconnect();
        return result;
    }

    // Verify socket state after key exchange
    int error = 0;
    socklen_t len = sizeof(error);
    int retval = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
    if (retval != 0 || error != 0) {
        std::cout << "Socket error after key exchange: " << strerror(error) << std::endl;
        NetworkClient::disconnect();
        return ErrorCode::CONNECTION_FAILED;
    }
    std::cout << "Socket verified in good state after key exchange" << std::endl;

    // Send service request for ssh-connection
    std::cout << "Sending service request..." << std::endl;
    SSHPacket serviceRequest(static_cast<Byte>(MsgType::SERVICE_REQUEST));
    std::string serviceName = "ssh-connection";
    Bytes serviceNameBytes(serviceName.begin(), serviceName.end());
    serviceRequest.setPayload(serviceNameBytes);
    
    result = sendSSHPacket(serviceRequest);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to send service request: " << static_cast<int>(result) << std::endl;
        return result;
    }
    
    // Wait for service accept
    std::cout << "Waiting for service accept..." << std::endl;
    SSHPacket serviceAccept;
    result = recvSSHPacket(serviceAccept);
    if (result != ErrorCode::SUCCESS) {
        std::cout << "Failed to receive service accept: " << static_cast<int>(result) << std::endl;
        return result;
    }
    if (serviceAccept.getMsgType() != static_cast<Byte>(MsgType::SERVICE_ACCEPT)) {
        std::cout << "Invalid message type received: " << static_cast<int>(serviceAccept.getMsgType()) << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    std::cout << "Service request accepted" << std::endl;

    return ErrorCode::SUCCESS;
}

ErrorCode SSHClient::recvSSHPacket(SSHPacket& packet, unsigned int timeout_ms) {
    if (!encryptionEnabled)
        return NetworkClient::recvTCPPacket(packet, SSH_MAX_PACKET_SIZE, timeout_ms);

    Byte encryptedLengthBlock[crypto::AES256::BLOCK_SIZE];
    if (!recvBytes(encryptedLengthBlock, sizeof(encryptedLengthBlock), timeout_ms))
        return ErrorCode::TIMEOUT;
    Bytes encryptedLengthBytes(encryptedLengthBlock, encryptedLengthBlock + sizeof(encryptedLengthBlock));

    Bytes packetLengthBytes = decryptBytes(encryptedLengthBytes);
    uint32_t packetLength =
        (static_cast<uint32_t>(packetLengthBytes[0]) << 24) |
        (static_cast<uint32_t>(packetLengthBytes[1]) << 16) |
        (static_cast<uint32_t>(packetLengthBytes[2]) <<  8) |
         static_cast<uint32_t>(packetLengthBytes[3]);

    if (packetLength > SSH_MAX_PACKET_SIZE)
        return ErrorCode::PROTOCOL_ERROR;

    // Calculate remaining data to read (excluding the first block we already read)
    size_t remainingEncryptedSize = packetLength - (crypto::AES256::BLOCK_SIZE - 4);
    remainingEncryptedSize += crypto::HMACSHA256::DIGEST_SIZE; // Add MAC size
    
    Bytes packetData(remainingEncryptedSize);
    if (!recvBytes(packetData.data(), packetData.size(), timeout_ms))
        return ErrorCode::TIMEOUT;
    
    Bytes mac(packetData.end() - crypto::HMACSHA256::DIGEST_SIZE, packetData.end());
    packetData.resize(packetData.size() - crypto::HMACSHA256::DIGEST_SIZE);

    Bytes encryptedPayload;
    encryptedPayload.insert(encryptedPayload.end(), encryptedLengthBytes.begin(), encryptedLengthBytes.begin());
    encryptedPayload.insert(encryptedPayload.end(), packetData.begin(), packetData.end());

    Bytes payload = decryptBytes(encryptedPayload);
    Bytes expectedMac = computeMAC(payload, false);
    if (!std::equal(mac.begin(), mac.end(), expectedMac.begin(), expectedMac.end()))
        return ErrorCode::DECRYPTION_ERROR;
    
    // Deserialize the packet
    try {
        packet.deserialize(payload);
    } catch (const std::exception& e) {
        return ErrorCode::PROTOCOL_ERROR;
    }
    
    return ErrorCode::SUCCESS;
}

ErrorCode SSHClient::sendSSHPacket(SSHPacket& packet) {
    if (!encryptionEnabled)
        return NetworkClient::sendTCPPacket(packet);

    std::cout << "Sending encrypted packet (type: " << static_cast<int>(packet.getMsgType()) << ")" << std::endl;

    try {
        Bytes data = packet.serialize();
        Bytes mac = computeMAC(data, true);
        std::cout << "MAC computed, size: " << mac.size() << " bytes" << std::endl;

        Bytes encryptedData = encryptBytes(data);
        std::cout << "Packet data encrypted, size: " << encryptedData.size() << " bytes" << std::endl;
        encryptedData.insert(encryptedData.end(), mac.begin(), mac.end());

        size_t bytesSent = send(sockfd, encryptedData.data(), encryptedData.size(), 0);
        if (bytesSent < 0 || bytesSent != encryptedData.size()) {
            std::cout << "Failed to send encrypted data, error: " << strerror(errno) << std::endl;
            return ErrorCode::PROTOCOL_ERROR;
        }

        std::cout << "Successfully sent " << bytesSent << " bytes" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Exception during send: " << e.what() << std::endl;
        return ErrorCode::PROTOCOL_ERROR;
    }
    
    return ErrorCode::SUCCESS;
}
    
}; // namespace ssh
