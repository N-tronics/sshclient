#include <SSHUtils.hpp>

namespace ssh {

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

void SSHUtils::deriveKeys(const Bytes& sharedSecret, const Bytes& exchangeHash) {
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

Bytes SSHUtils::deriveKeyData(const Bytes& sharedSecret, const Bytes& exchangeHash, char purpose, size_t keySize) {
    // K1 = HASH(K || H || X || sessin_id)
    // K = sharedSecret, H = exchangeHash, X = purpse byte
    Bytes input;
    input.insert(input.end(), sharedSecret.begin(), sharedSecret.end());
    input.insert(input.end(), exchangeHash.begin(), exchangeHash.end());
    input.push_back(static_cast<Byte>(purpose));
    input.insert(input.end(), sessionId.begin(), sessionId.end());

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

} // namespace ssh
