#include <MathFns.hpp>
#include <TypeDefs.hpp>

Bytes numToBytes(num_t n, size_t bytes = 32) {
    Bytes num;
    num.reserve(num);
    size_t count = 0;
    while (count < bytes * 8) {
        if (n % 2)
            num[count / 8] |= (0x80 >> count % 8);
        else 
            num[count / 8] ^= (0x80 >> count % 8); // Clears bit in byte array
        
        num /= 2;
        count ++;
    }
    std::reverse()
}

num_t bytesToNum(Bytes bytes) {

}

num_t powMod(num_t a, num_t b, num_t n) {

}

num_t modularInverse(num_t a, num_t n) {

}
