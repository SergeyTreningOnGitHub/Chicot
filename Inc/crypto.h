#pragma once

#include "utils.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
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
    
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(curve_nid);
 
    if(curve == NULL){
        EXIT_WITH_MSG("Can't get curve");
    }

    EC_POINT *point = EC_POINT_new(curve);
    if (point == NULL){
        EXIT_WITH_MSG("Can't allocate point");
    }

    if(!EC_POINT_oct2point(curve, point, pub_key.data(), pub_key.size(), NULL))
    {
        EXIT_WITH_MSG("Can't get point");
    }
    
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if(!EC_KEY_set_public_key(ec_key, point)){
        EXIT_WITH_MSG("Can't get ec key");
    }

    EVP_PKEY* pub_key_formed = EVP_PKEY_new();
    if(!EVP_PKEY_set1_EC_KEY(pub_key_formed, ec_key)){
        EXIT_WITH_MSG("Can't get evp key");
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
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

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pub_key_formed);
    EC_KEY_free(ec_key);
    EC_POINT_free(point);
    EC_GROUP_free(curve);
}
