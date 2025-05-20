#pragma once

#include <TypeDefs.hpp>

namespace crypto {
// Simple AES-256 implementation (implementation omitted for brevity)
// In a real implementation, this would be a proper AES-256 implementation
class AES256 {
public:
    static const size_t BLOCK_SIZE = 16;  // 128 bits
    static const size_t KEY_SIZE = 32;    // 256 bits
    
    AES256(const Bytes& key);    
    // Encrypt a single block
    void encryptBlock(const Bytes& plaintext, Bytes& ciphertext) const;    
    // Decrypt a single block
    void decryptBlock(const Bytes& ciphertext, Bytes& plaintext) const;    
private:
    // Simple encryption function for demonstration purposes only
    // NOT SECURE - DO NOT USE IN PRODUCTION
    void simpleEncrypt(const Bytes& plaintext, Bytes& ciphertext) const;    
    // Simple decryption function for demonstration purposes only
    // NOT SECURE - DO NOT USE IN PRODUCTION
    void simpleDecrypt(const Bytes& ciphertext, Bytes& plaintext) const;    
    Bytes m_key;
};


// AES-256 in CBC mode
class AES256CBC {
public:
    AES256CBC(const Bytes& key, const Bytes& iv);
    // Encrypt data using CBC mode
    Bytes encrypt(const Bytes& plaintext) const;    
    // Decrypt data using CBC mode
    Bytes decrypt(const Bytes& ciphertext) const;
private:
    // PKCS#7 padding
    static Bytes pkcs7Pad(const Bytes& data, size_t blockSize);
    // PKCS#7 unpadding
    static Bytes pkcs7Unpad(const Bytes& data);    
    AES256 m_aes;
    Bytes m_iv;
};

} // namespace crypto
