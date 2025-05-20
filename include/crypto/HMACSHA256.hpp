#pragma once

#include <crypto/SHA256.hpp>
#include <TypeDefs.hpp>

namespace crypto {

// HMAC-SHA256 implementation
class HMACSHA256 {
public:
    static const size_t DIGEST_SIZE = SHA256::DIGEST_SIZE;
    
    // Compute HMAC-SHA256 using the specified key
    static Bytes compute(const Bytes& key, const Bytes& data);
};

} // namespace crypto
