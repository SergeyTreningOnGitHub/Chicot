#pragma once
#include "crypto.h"

class Wallet{    
    EVP_PKEY* params_;
    EVP_PKEY* ec_key_;

    void gen_key_params(){
        int curve_nid = GetCurveNid();
        
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
        
        /* Generate the key */
        if (!EVP_PKEY_keygen(key_ctx, &ec_key_)) 
            goto err;

        //ec_key_ = EVP_PKEY_get1_EC_KEY(pkey);        
    }

public:
    Wallet() : params_(NULL), ec_key_(NULL){}

    void SavePrivate(const string& filename){
        BIO* file = BIO_new_file((filename + ".pem").c_str(), "w");        

        int len = PEM_write_bio_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL);
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

        assert(ec_key_ != NULL);


        BIO_free(file);
    }

    void GenKeys(){
        gen_key_params();
        gen_keys();
        SavePrivate("private");

    }

    EC_Sign SignMessage(const ByteMessage& msg){
        EVP_MD_CTX *mdctx = NULL;
        int ret = 0;
        
        if(!(mdctx = EVP_MD_CTX_create())) {
            goto err;
        }
 
        if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_key_)){ 
            goto err;
        }
 
        if(1 != EVP_DigestSignUpdate(mdctx, msg.data(), msg.size())){
             goto err;
        }
 
        EC_Sign sig_res;
        uint32_t size_sig;

        if(1 != EVP_DigestSignFinal(mdctx, NULL, &size_sig)){
            goto err;
        }

        sig_res.resize(size_sig);
        if(1 != EVP_DigestSignFinal(mdctx, sig_res.data(), sig_res.size())){
            goto err;
        }       

        EVP_MD_CTX_destroy(mdctx);
        return sig_res;
    }

    PrivateKey GetPrivateKey(){
        PrivateKey res;
        uint32_t priv_key_len = 0;
        if (!EVP_PKEY_get_raw_private_key(ec_key_, NULL, &priv_key_len)){
            return {};                        
        }

        res.resize(priv_key_len);

        if(!EVP_PKEY_get_raw_private_key(ec_key_, res.data(), res.size()){
            return {};
        }
        return res;
    }

    PublicKey GetPublicKey(){
        PublicKey res;
        uint32_t pub_key_len = 0;
        if (!EVP_PKEY_get_raw_public_key(ec_key_, NULL, &pub_key_len)){
            return {};
                                      
        }

        res.resize(pub_key_len);

        if(!EVP_PKEY_get_raw_pubic_key(ec_key_, res.data(), res.size()){
            return {};
        }

        return res;
    }        
};