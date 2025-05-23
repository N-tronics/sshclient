#include <SSHUtils.hpp>
#include <iostream>
#include <fstream>
#include <MathFns.hpp>

namespace ssh {

SSHUtils::SSHUtils(const NetUtils& utils) {
    sockfd = utils.getSockfd();
}

Bytes SSHUtils::computeExchangeHash(
    const Bytes& clientProtocol,
    const Bytes& serverProtocol,
    const Bytes& clientKexInit,
    const Bytes& serverKexInit,
    const Bytes& clientPublicKey,
    const Bytes& serverPublicKey,
    const Bytes& sharedSecretKey
) {
    Bytes inputs;
    inputs.insert(inputs.end(), clientProtocol.begin(), clientProtocol.end());
    inputs.insert(inputs.end(), serverProtocol.begin(), serverProtocol.end());
    inputs.insert(inputs.end(), clientKexInit.begin(), clientKexInit.end());
    inputs.insert(inputs.end(), serverKexInit.begin(), serverKexInit.end());
    inputs.insert(inputs.end(), partnerRSAKey.begin(), partnerRSAKey.end());
    inputs.insert(inputs.end(), clientPublicKey.begin(), clientPublicKey.end());
    inputs.insert(inputs.end(), serverPublicKey.begin(), serverPublicKey.end());
    inputs.insert(inputs.end(), sharedSecretKey.begin(), sharedSecretKey.end());

    return crypto::SHA256::computeHash(inputs);
}

void SSHUtils::deriveKeys(const Bytes& sharedSecret, const Bytes& exchangeHash, std::string id) {
    std::cout << "Deriving Keys from shared secret and exchange hash..." << std::endl;

    encryptionKey = deriveKeyData(sharedSecret, exchangeHash, 'C', crypto::AES256::KEY_SIZE);
    encryptionIV = deriveKeyData(sharedSecret, exchangeHash, 'A', crypto::AES256::BLOCK_SIZE);
    integrityKey = deriveKeyData(sharedSecret, exchangeHash, 'E', crypto::HMACSHA256::DIGEST_SIZE);
    
    std::cout << "AES Encryption Key: "; printBytes(std::cout, encryptionKey); std::cout << std::endl;
    std::cout << "AES Encryption  IV: "; printBytes(std::cout, encryptionIV); std::cout << std::endl;
    std::cout << "HMAC Integrity Key: "; printBytes(std::cout, integrityKey); std::cout << std::endl;
    std::cout << std::endl;

    try {
        aes = std::make_unique<crypto::AES256CBC>(encryptionKey, encryptionIV);
        std::cout << "AES Intialized successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "AES Initialization failed: " << e.what() << std::endl;
        throw;
    }
}

Bytes SSHUtils::deriveKeyData(const Bytes& sharedSecret, const Bytes& exchangeHash, char purpose, size_t keySize) {
    // K1 = HASH(K || H || X || sessin_id)
    // K = sharedSecret, H = exchangeHash, X = purpse byte
    Bytes input;
    input.insert(input.end(), sharedSecret.begin(), sharedSecret.end());
    input.insert(input.end(), exchangeHash.begin(), exchangeHash.end());
    input.push_back(static_cast<Byte>(purpose));
    input.insert(input.end(), sessionID.begin(), sessionID.end());
    std::cout << "deriveKeyData: sessionID: "; printBytes(std::cout, sessionID); std::cout << std::endl;

    Bytes result = crypto::SHA256::computeHash(input);
    while (result.size() < keySize) {
        input.clear();
        input.insert(input.end(), sharedSecret.begin(), sharedSecret.end());
        input.insert(input.end(), exchangeHash.begin(), exchangeHash.end());
        input.insert(input.end(), result.begin(), result.end());

        Bytes additionalData = crypto::SHA256::computeHash(input);
        result.insert(result.end(), additionalData.begin(), additionalData.end());
    }
    result.resize(keySize);
    return result;
}

Bytes SSHUtils::encryptBytes(const Bytes& data) const {
    if (!aes)
        throw std::runtime_error("Encryption not initialized");
    
    try {
        return aes->encrypt(data);
    } catch (const std::exception& e) {
        std::cout << "Encryption failed: " << e.what() << std::endl;
        throw;
    }
}

Bytes SSHUtils::decryptBytes(const Bytes& data) const {
    if (!aes)
        throw std::runtime_error("Encryption not initialized");
    
    return aes->decrypt(data);
}

Bytes SSHUtils::decryptBlock(const Bytes& data) const {
    if (!aes)
        throw std::runtime_error("Encryption not initialized");
    
    return aes->decryptBlock(data);
}

Bytes SSHUtils::computeMAC(const Bytes& data, bool sending) const {
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

ErrorCode SSHUtils::recvSSHPacket(SSHPacket& packet, uint32_t timeout_ms) const {
    Bytes encryptedLengthBytes;
    if (!recvBytes(encryptedLengthBytes, crypto::AES256::BLOCK_SIZE, timeout_ms))
        return ErrorCode::TIMEOUT;

    std::cout << "Encrypted Length Bytes: "; printBytes(std::cout, encryptedLengthBytes); std::cout << std::endl;
    Bytes packetLengthBytes = decryptBlock(encryptedLengthBytes);
    uint32_t packetLength =
        (static_cast<uint32_t>(packetLengthBytes[0]) << 24) |
        (static_cast<uint32_t>(packetLengthBytes[1]) << 16) |
        (static_cast<uint32_t>(packetLengthBytes[2]) <<  8) |
         static_cast<uint32_t>(packetLengthBytes[3]);
    std::cout << "Encrypted packet length: " << packetLength << std::endl;
    if (packetLength > SSHPacket::MAX_SIZE)
        return ErrorCode::PROTOCOL_ERROR;

    // Calculate remaining data to read (excluding the first block we already read)
    size_t remainingEncryptedSize = packetLength - (crypto::AES256::BLOCK_SIZE - 4);
    //packetLength += crypto::AES256::BLOCK_SIZE - ((remainingEncryptedSize + crypto::AES256::BLOCK_SIZE) % crypto::AES256::BLOCK_SIZE);
    remainingEncryptedSize += crypto::AES256::BLOCK_SIZE - ((4 + packetLength) % crypto::AES256::BLOCK_SIZE);
    remainingEncryptedSize += crypto::HMACSHA256::DIGEST_SIZE; // Add MAC size
    std::cout << "Bytes left to read: " << remainingEncryptedSize << std::endl; 
    Bytes packetData;
    if (!recvBytes(packetData, remainingEncryptedSize, timeout_ms))
        return ErrorCode::TIMEOUT;
    std::cout << "encrypted packet data with MAC: ", printBytes(std::cout, packetData); std::cout << std::endl;
    
    Bytes mac(packetData.end() - crypto::HMACSHA256::DIGEST_SIZE, packetData.end());
    packetData.resize(packetData.size() - crypto::HMACSHA256::DIGEST_SIZE);

    Bytes encryptedPacket = encryptedLengthBytes;
    // encryptedPacket.reserve(crypto::AES256::BLOCK_SIZE + packetData.size());
    std::cout << "Encrypted packet length: " << crypto::AES256::BLOCK_SIZE + packetData.size() << std::endl;
    encryptedPacket.insert(encryptedPacket.begin() + crypto::AES256::BLOCK_SIZE, packetData.begin(), packetData.end());
    
    std::cout << "encrypted packet data without MAC: ", printBytes(std::cout, packetData); std::cout << std::endl;
    std::cout << "encrypted packet: "; printBytes(std::cout , encryptedPacket); std::cout << std::endl;
    Bytes decryptedPacket = decryptBytes(encryptedPacket);
    Bytes expectedMac = computeMAC(decryptedPacket, false);
    if (!std::equal(mac.begin(), mac.end(), expectedMac.begin(), expectedMac.end()))
        return ErrorCode::DECRYPTION_ERROR;
    // Deserialize the packet
    try {
        packet.deserialize(decryptedPacket);
    } catch (const std::exception& e) {
        return ErrorCode::PROTOCOL_ERROR;
    }
    
    return ErrorCode::SUCCESS;
}

ErrorCode SSHUtils::sendSSHPacket(SSHPacket& packet) const {
    std::cout << "Sending encrypted packet (type: " << static_cast<int>(packet.getMsgType()) << ")" << std::endl;

    try {
        Bytes data = packet.serialize();
    std::cout << "Packet Data: "; printBytes(std::cout, data); std::cout << std::endl;
        Bytes mac = computeMAC(data, true);
        std::cout << "MAC computed, size: " << mac.size() << " bytes" << std::endl;

        Bytes encryptedData = encryptBytes(data);
        std::cout << "Packet data encrypted, size: " << encryptedData.size() << " bytes" << std::endl;
        encryptedData.insert(encryptedData.end(), mac.begin(), mac.end());
    
    std::cout << "Packet data encrypted size after mac addition: " << encryptedData.size() << std::endl;
    std::cout << "Packet Encrypted Data: " << std::endl; printBytes(std::cout, encryptedData); std::cout << std::endl;
        
        size_t bytesSent = send(*sockfd, encryptedData.data(), encryptedData.size(), 0);
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

} // namespace ssh
