#include <iostream>
#include <string>

#include <crypto/SHA256.hpp>
#include <crypto/Random.hpp>
#include <TypeDefs.hpp>

void coutByteAsHex(Byte b) {
    std::cout << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F) << std::dec;
}

int main() {
    std::string str = "Hello!";
    Bytes data (str.begin(), str.end());
    Bytes hash = crypto::SHA256::computeHash(data);
    for (Byte b : hash) {
        coutByteAsHex(b);
    }
    std::cout << std::endl;

    std::cout << crypto::Random::generateNum(256) << std::endl;
}
