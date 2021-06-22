#pragma once
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <vector>
#include <algorithm>
#include <cassert>
#include <iostream>

using INT512 = boost::multiprecision::int512_t;
using INT256 = boost::multiprecision::int256_t;
using ByteMessage = std::vector<uint8_t>;

constexpr uint32_t SHA256_SIZE = 32;



INT256 GenDigest(const ByteMessage& msg){        
    assert(EVP_MD_size(EVP_sha256()) == SHA256_SIZE);
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();        
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, msg.data(), msg.size());
    
    uint8_t fictive_buf[SHA256_SIZE];        
    uint32_t fictive_len;

    EVP_DigestFinal_ex(mdctx, fictive_buf, &fictive_len);
    EVP_MD_CTX_free(mdctx);
    INT256 res;
    import_bits(res, std::begin(fictive_buf), std::begin(fictive_buf) + SHA256_SIZE);
    return res;
}