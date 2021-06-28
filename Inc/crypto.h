#pragma once

#include "utils.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <array>
#include <vector>
#include <algorithm>
#include <cassert>
#include <iostream>


constexpr uint32_t SHA256_SIZE = 32;

using EC_Sign    = std::vector<uint8_t>;
using PrivateKey = std::vector<uint8_t>;
using PublicKey  = std::vector<uint8_t>;
using SHA256_Digest = std::vector<uint8_t>;
using ByteMessage = std::vector<uint8_t>;

int GetCurveNid(){    
    return NID_secp256k1;
}

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

bool VerifySign(const ByteMessage& msg, const EC_Sign& sig, const PublicKey& pub_key){
    int curve_nid = GetCurveNid();

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

    EVP_PKEY* pub_key_formed = EVP_PKEY_new_raw_public_key(curve_nid, NULL, pub_key.data(), pub_key.size());

    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub_key_formed)){ 
        EXIT_WITH_MSG("Can't init verify operation");
    }

    if(1 != EVP_DigestVerifyUpdate(mdctx, msg.data(), msg.size())){
        EXIT_WITH_MSG("Error verifing message");
    }

    if(1 == EVP_DigestVerifyFinal(mdctx, sig.data(), sig.size()))
    {
        return true;
    }
    else
    {
        return false;
    }

    EVP_PKEY_free(pub_key_formed);
    EVP_MD_CTX_free(mdctx);
}
