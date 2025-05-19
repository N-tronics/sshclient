#pragma once

#include <TypeDefs.hpp>

namespace crypto {

class SHA256 {
public:
    static const size_t DIGEST_SIZE = 32;
    
    static Bytes computeHash(const Bytes& data);
};

} // namespace crypto

