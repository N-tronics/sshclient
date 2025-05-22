#pragma once

#include <TypeDefs.hpp>

namespace crypto {

namespace rsa {

typedef struct RSAKey {
    num_t exp;
    num_t prime;
} RSAKey;

class RSA {
private:
    num_t publicExp;
    num_t privateExp;
    num_t prime;
public:
    RSA() {}
    
    void generateKeyPair(size_t keySize = 256);
    RSAKey getPublicKey() const;
    RSAKey getPrivateKey() const;
    
    static Bytes encryptBytes(const Bytes& bytes, const RSAKey& key);
    static Bytes decryptBytes(const Bytes& cipher, const RSAKey& key);
    
    Bytes signBytes(const Bytes& bytes) const;
    bool verifySignature(const Bytes& hash, const Bytes& signature, const RSAKey& pubKey) const;
};

} // namespace rsa

} // namespace crypto
