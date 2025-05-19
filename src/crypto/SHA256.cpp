#include <crypto/Crypto.hpp>
#include <TypeDefs.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iostream>

namespace crypto {

Bytes SHA256::computeHash(const Bytes& data) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    Byte output[EVP_MAX_MD_SIZE];
    unsigned int outLen;

    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal(ctx, output, &outLen);
    EVP_MD_CTX_destroy(ctx);
    
    return Bytes(output, output + outLen);
}

} // namespace
