#include <crypto/Crypto.hpp>
#include <boost/integer/common_factor_rt.hpp>
#include <boost/integer/mod_inverse.hpp>
#include <MathFns.hpp>

namespace crypto {

namespace rsa {

std::ostream& operator<<(std::ostream& os, const Key& key) {
    os << "(" << key.exp << ", " << key.prime << ")";
    return os;
}

void RSA::generateKeyPair(size_t keySize) {
    num_t p = Random::generatePrimeNum(keySize / 2);
    num_t q = Random::generatePrimeNum(keySize / 2);
    prime = p * q;
    num_t phi = (p - 1) * (q - 1);

    do {
    publicExp = Random::generateNum(keySize);
    } while (boost::math::gcd(publicExp, phi) != 1);

    privateExp = boost::integer::mod_inverse(publicExp, phi);
}
    
Key RSA::getPublicKey() const {
    return Key(publicExp, prime);
}

Key RSA::getPrivateKey() const {
    return Key(privateExp, prime);
}

Bytes RSA::encryptBytes(const Bytes& text, const Key& key) {
    return numToBytes(powMod(bytesToNum(text), key.exp, key.prime));
}

Bytes RSA::decryptBytes(const Bytes& cipher, const Key& key) {
    return numToBytes(powMod(bytesToNum(cipher), key.exp, key.prime));
}

Bytes RSA::signBytes(const Bytes& data) const {
    return encryptBytes(data, Key(privateExp, prime));
}

bool RSA::verifySignature(const Bytes& hash, const Bytes& signature, const Key& pubKey) const {
    Bytes expectedHash = decryptBytes(signature, pubKey);
    return std::equal(expectedHash.begin(), expectedHash.end(), hash.begin(), hash.end());
}

} // namespace rsa

} // namespace crypto
