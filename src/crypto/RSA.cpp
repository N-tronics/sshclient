#include <Crypto.hpp>
#include <boost/integer/common_factor_rt.hpp>
#include <boost/integer/mod_inverse.hpp>
#include <MathFns.hpp>

namespace crypto {

namespace rsa {

std::ostream& operator<<(std::ostream& os, const RSAKey& key) {
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
    
RSAKey RSA::getPublicKey() const {
    return RSAKey(publicExp, prime);
}

RSAKey RSA::getPrivateKey() const {
    return RSAKey(privateExp, prime);
}

Bytes RSA::encryptBytes(const Bytes& text, const RSAKey& key) {
    return numToBytes(powMod(bytesToNum(text), key.exp, key.prime));
}

Bytes RSA::decryptBytes(const Bytes& cipher, const RSAKey& key) {
    return numToBytes(powMod(bytesToNum(cipher), key.exp, key.prime));
}

Bytes RSA::signBytes(const Bytes& data) const {
    return encryptBytes(data, RSAKey(privateExp, prime));
}

bool RSA::verifySignature(const Bytes& hash, const Bytes& signature, const RSAKey& pubKey) const {
    Bytes expectedHash = decryptBytes(signature, pubKey);
    std::cout << "RSA::VerifySignature: "; printBytes(std::cout, expectedHash); std::cout << std::endl;
    bool T = std::equal(expectedHash.begin(), expectedHash.end(), hash.begin(), hash.end());
    bool t = true;
    if (hash.size() != expectedHash.size())
        t = false;
    else {
        for (size_t i = 0; i < hash.size(); i++) {
            if (hash[i] != expectedHash[i]) {
                t = false;
                break;
            }
        }
    }
    std::cout << t << " " << T << std::endl;
    return t;
}

} // namespace rsa

} // namespace crypto
