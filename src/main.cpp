#include <iostream>
#include <string>

#include <TypeDefs.hpp>
#include <MathFns.hpp>

void coutByteAsHex(Byte b) {
    std::cout << std::hex << ((b & 0xF0) >> 4) << (b & 0x0F) << std::dec;
}

int main() {
    num_t n("0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9");
    Bytes bytes = numToBytes(n);
    for (Byte b : bytes)
        coutByteAsHex(b);
    std::cout << std::endl;
    num_t m = bytesToNum(bytes);
    std::cout << m << std::endl << (m == n) << std::endl;
}
