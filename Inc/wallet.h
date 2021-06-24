#pragma once
#include "crypto.h"


constexpr uint32_t SHA256_SIZE = 32;

using SHA256_Digest = std::array<uint8_t, SHA256_SIZE>;
using ByteMessage = std::vector<uint8_t>;


class Wallet{    
    EVP_PKEY* params_;
    EC_KEY* ec_key_;

    void gen_key_params(){
        const char* curve_name = "secp256k1";
        int curve_nid = EC_curve_nist2nid(curve_name);
        if (curve_nid == NID_undef) {
            // try converting the shortname (sn) to nid (numberic id)
            curve_nid = OBJ_sn2nid(curve_name);
        }
        
        /* Create the context for generating the parameters */
        EVP_PKEY_CTX* pctx;
        if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) 
            goto err;
        if(!EVP_PKEY_paramgen_init(pctx)) 
            goto err;
        
        if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid)) 
            goto err;		

            /* Generate parameters */
        if (!EVP_PKEY_paramgen(pctx, &params_)) 
            goto err;

        EVP_PKEY_CTX_free(pctx);
    }

    void gen_keys(){
        EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(params_, NULL);

        if(!EVP_PKEY_keygen_init(key_ctx)) 
            goto err;

        EVP_PKEY* pkey = NULL;
        /* Generate the key */
        if (!EVP_PKEY_keygen(key_ctx, &pkey)) 
            goto err;

        ec_key_ = EVP_PKEY_get1_EC_KEY(pkey);        
    }

public:
    Wallet() : params_(NULL), ec_key_(NULL){}

    void SavePrivate(const string& filename){
        BIO* file = BIO_new_file((filename + ".pem").c_str(), "w");

        int len = PEM_write_bio_ECPrivateKey(file, ec_key_, NULL, NULL, 0, NULL, NULL);
        if (len <= 0) {
            error_and_exit("Could not write the private key");
        }

        BIO_free(file);
    }

    void LoadPrivate(const string& filename){
        BIO* file = BIO_new_file((filename + ".pem").c_str(), "r");

        ec_key_ = PEM_read_bio_PrivateKey(file, NULL, NULL, NULL); 
        if (ec_key_)
            printf("read private key successfully\n");
        else 
            printf("cound not read private key!\n");

        ERR_print_errors_fp(stdout);

        assert(ed_key_ != NULL);


        BIO_free(file);
    }

    void GenKeys(){
        gen_key_params();
        gen_keys();
        SavePrivate("private");
    }    
};