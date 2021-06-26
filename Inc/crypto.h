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

using EC_Sign    = std::vector<uint8_t>;
using PrivateKey = std::vector<uint8_t>;
using PublicKey  = std::vector<uint8_t>;
using SHA256_Digest = std::vector<uint8_t>;
using ByteMessage = std::vector<uint8_t>;

int GetCurveNid(){
    const char* curve_name = "secp256k1";
    int curve_nid = EC_curve_nist2nid(curve_name);
    if (curve_nid == NID_undef) {
        // try converting the shortname (sn) to nid (numberic id)
        curve_nid = OBJ_sn2nid(curve_name);
    }
    return curve_nid;
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

bool VerifySign(const ByteMessage& msg, const EcSign& sig, const PublicKey& pub_key){
    int curve_nid = GetCurveNid();

    EVP_PKEY* pub_key_formed = EVP_PKEY_new_raw_public_key(curve_nid, NULL, pub_key.data(), pub_key.size());

    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub_key_formed)){ 
        goto err;
    }

    if(1 != EVP_DigestVerifyUpdate(mdctx, msg.data(), msg.size())){
         goto err;
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
}
