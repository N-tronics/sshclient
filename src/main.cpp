#include <iostream>

#include <TCPPacket.hpp>
#include <Types.hpp>
#include <NetworkClient.hpp>
#include <SSHClient.hpp>
#include <crypto/Crypto.hpp>
#include <MathFns.hpp>

std::ostream& operator<<(std::ostream& os, const Bytes& bytes) {
    os << "0x";
    for (Byte b : bytes)
        os << std::hex << static_cast<int>(b);
    os << std::dec;
    return os;
}

int main() {
    crypto::rsa::RSA rsa;
    rsa.generateKeyPair();
    std::cout << "Public Key : " << rsa.getPublicKey() << std::endl;
    std::cout << "Private Key: " << rsa.getPrivateKey() << std::endl;

    Bytes m { 0x12, 0x34, 0xab, 0xcd };
    std::cout << "Message: " << m << std::endl;

    Bytes cipher = crypto::rsa::RSA::encryptBytes(m, rsa.getPrivateKey());
    std::cout << "Cipher: " << cipher;

    Bytes msg = crypto::rsa::RSA::decryptBytes(cipher, rsa.getPublicKey());
    std::cout << "Message: " << msg << std::endl;
    
}
