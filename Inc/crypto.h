#pragma once

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <array>
#include <vector>
#include <algorithm>
#include <cassert>
#include <iostream>


constexpr uint32_t SHA256_SIZE = 32;

using SHA256_Digest = std::array<uint8_t, SHA256_SIZE>;
using ByteMessage = std::vector<uint8_t>;


SHA256_Digest GenDigest(const ByteMessage& msg){        
    assert(EVP_MD_size(EVP_sha256()) == SHA256_SIZE);
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();        
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, msg.data(), msg.size());
    
    SHA256_Digest res;        
    uint32_t fictive_len;

    EVP_DigestFinal_ex(mdctx, res.data(), &fictive_len);
    EVP_MD_CTX_free(mdctx);
    return res;
}
