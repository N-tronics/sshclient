#pragma once

#include <TypeDefs.hpp>

namespace crypto {

// HMAC-SHA256 implementation
class HMACSHA256 {
public:
    static const size_t DIGEST_SIZE = SHA256::DIGEST_SIZE;
    
    // Compute HMAC-SHA256 using the specified key
    static Bytes compute(const Bytes& key, const Bytes& data) {
        // This is a simplified HMAC implementation
        // In a real implementation, this would be a proper HMAC-SHA256 implementation
        const size_t BLOCK_SIZE = 64; // SHA-256 block size
        
        // Prepare key
        Bytes processedKey = key;
        if (processedKey.size() > BLOCK_SIZE) {
            // If key is longer than block size, hash it
            processedKey = SHA256::compute(processedKey);
        }
        if (processedKey.size() < BLOCK_SIZE) {
            // If key is shorter than block size, pad it with zeros
            processedKey.resize(BLOCK_SIZE, 0);
        }
        
        // Create inner and outer padding
        Bytes ipad(BLOCK_SIZE, 0x36);
        Bytes opad(BLOCK_SIZE, 0x5C);
        
        // XOR key with pads
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            ipad[i] ^= processedKey[i];
            opad[i] ^= processedKey[i];
        }
        
        // Compute inner hash: SHA256(ipad || data)
        Bytes innerData = ipad;
        innerData.insert(innerData.end(), data.begin(), data.end());
        Bytes innerHash = SHA256::compute(innerData);
        
        // Compute outer hash: SHA256(opad || innerHash)
        Bytes outerData = opad;
        outerData.insert(outerData.end(), innerHash.begin(), innerHash.end());
        return SHA256::compute(outerData);
    }
};

} // namespace crypto
