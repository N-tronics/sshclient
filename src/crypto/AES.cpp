#include <crypto/Crypto.hpp>
#include <TypeDefs.hpp>

namespace crypto {

AES256::AES256(const Bytes& key) {
    if (key.size() != KEY_SIZE) {
        throw std::invalid_argument("AES-256 key must be 32 bytes");
    }
    m_key = key;
}

// Encrypt a single block
void AES256::encryptBlock(const Bytes& plaintext, Bytes& ciphertext) const {
    if (plaintext.size() != BLOCK_SIZE) {
        throw std::invalid_argument("AES plaintext block must be 16 bytes");
    }
    
    ciphertext.resize(BLOCK_SIZE);
    
    // Simple encryption for demonstration purposes only
    // NOT SECURE - DO NOT USE IN PRODUCTION
    simpleEncrypt(plaintext, ciphertext);
}

// Decrypt a single block
void AES256::decryptBlock(const Bytes& ciphertext, Bytes& plaintext) const {
    if (ciphertext.size() != BLOCK_SIZE) {
        throw std::invalid_argument("AES ciphertext block must be 16 bytes");
    }
    
    plaintext.resize(BLOCK_SIZE);
    
    // Simple decryption for demonstration purposes only
    // NOT SECURE - DO NOT USE IN PRODUCTION
    simpleDecrypt(ciphertext, plaintext);
}

// Simple encryption function for demonstration purposes only
// NOT SECURE - DO NOT USE IN PRODUCTION
void AES256::simpleEncrypt(const Bytes& plaintext, Bytes& ciphertext) const {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        ciphertext[i] = plaintext[i] ^ m_key[i % KEY_SIZE];
    }
}

// Simple decryption function for demonstration purposes only
// NOT SECURE - DO NOT USE IN PRODUCTION
void AES256::simpleDecrypt(const Bytes& ciphertext, Bytes& plaintext) const {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        plaintext[i] = ciphertext[i] ^ m_key[i % KEY_SIZE];
    }
}


AES256CBC::AES256CBC(const Bytes& key, const Bytes& iv) : m_aes(key) {
    if (iv.size() != AES256::BLOCK_SIZE) {
        throw std::invalid_argument("AES-CBC IV must be 16 bytes");
    }
    m_iv = iv;
}

// Encrypt data using CBC mode
Bytes AES256CBC::encrypt(const Bytes& plaintext) const {
    // Pad plaintext to a multiple of the block size using PKCS#7 padding
    Bytes paddedPlaintext = pkcs7Pad(plaintext, AES256::BLOCK_SIZE);
    
    // Initialize result vector
    Bytes ciphertext(paddedPlaintext.size());
    
    // Use the IV for the first block
    Bytes previousBlock = m_iv;
    
    // Encrypt each block
    for (size_t i = 0; i < paddedPlaintext.size(); i += AES256::BLOCK_SIZE) {
        // Extract current plaintext block
        Bytes plaintextBlock(paddedPlaintext.begin() + i, paddedPlaintext.begin() + i + AES256::BLOCK_SIZE);
        
        // XOR with previous ciphertext block (or IV for first block)
        for (size_t j = 0; j < AES256::BLOCK_SIZE; ++j) {
            plaintextBlock[j] ^= previousBlock[j];
        }
        
        // Encrypt the block
        Bytes ciphertextBlock(AES256::BLOCK_SIZE);
        m_aes.encryptBlock(plaintextBlock, ciphertextBlock);
        
        // Copy encrypted block to output
        std::copy(ciphertextBlock.begin(), ciphertextBlock.end(), ciphertext.begin() + i);
        
        // Save this block for next iteration
        previousBlock = ciphertextBlock;
    }
    
    return ciphertext;
}

// Decrypt data using CBC mode
Bytes AES256CBC::decrypt(const Bytes& ciphertext) const {
    // Validate ciphertext length
    if (ciphertext.size() % AES256::BLOCK_SIZE != 0) {
        throw std::invalid_argument("Ciphertext size must be a multiple of the block size");
    }
    
    // Initialize result vector
    Bytes plaintext(ciphertext.size());
    
    // Use the IV for the first block
    Bytes previousBlock = m_iv;
    
    // Decrypt each block
    for (size_t i = 0; i < ciphertext.size(); i += AES256::BLOCK_SIZE) {
        // Extract current ciphertext block
        Bytes ciphertextBlock(ciphertext.begin() + i, ciphertext.begin() + i + AES256::BLOCK_SIZE);
        
        // Decrypt the block
        Bytes plaintextBlock(AES256::BLOCK_SIZE);
        m_aes.decryptBlock(ciphertextBlock, plaintextBlock);
        
        // XOR with previous ciphertext block (or IV for first block)
        for (size_t j = 0; j < AES256::BLOCK_SIZE; ++j) {
            plaintextBlock[j] ^= previousBlock[j];
        }
        
        // Copy decrypted block to output
        std::copy(plaintextBlock.begin(), plaintextBlock.end(), plaintext.begin() + i);
        
        // Save this ciphertext block for next iteration
        previousBlock = ciphertextBlock;
    }
    
    // Remove padding
    return pkcs7Unpad(plaintext);
}

// PKCS#7 padding
Bytes AES256CBC::pkcs7Pad(const Bytes& data, size_t blockSize) {
    size_t paddingSize = blockSize - (data.size() % blockSize);
    Bytes padded = data;
    padded.resize(data.size() + paddingSize, static_cast<Byte>(paddingSize));
    return padded;
}

// PKCS#7 unpadding
Bytes AES256CBC::pkcs7Unpad(const Bytes& data) {
    if (data.empty()) {
        throw std::invalid_argument("Empty data cannot be unpadded");
    }
    
    size_t paddingSize = data.back();
    if (paddingSize == 0 || paddingSize > data.size()) {
        throw std::invalid_argument("Invalid PKCS#7 padding");
    }
    
    // Verify padding
    for (size_t i = data.size() - paddingSize; i < data.size(); ++i) {
        if (data[i] != paddingSize) {
            throw std::invalid_argument("Invalid PKCS#7 padding");
        }
    }
    
    return Bytes(data.begin(), data.end() - paddingSize);
}

} // namespace crypto
