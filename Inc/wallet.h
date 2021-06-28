#pragma once
#include "crypto.h"
#include <openssl/ec.h>
#include <openssl/pem.h>

class Wallet{    
    EVP_PKEY* params_;
    EVP_PKEY* ec_key_;

    void gen_key_params(){
        int curve_nid = GetCurveNid();
        
        EVP_PKEY_CTX* pctx;
        if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))){ 
            EXIT_WITH_MSG("Can't create EVP_PKEY context");            
        }

        if(!EVP_PKEY_paramgen_init(pctx)){ 
            EXIT_WITH_MSG("Can't init paramgen");
        }
        
        if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid)){ 
            EXIT_WITH_MSG("Can't set paramgen");
        }		

        if (!EVP_PKEY_paramgen(pctx, &params_)){ 
            EXIT_WITH_MSG("Can't generate params");
        }

        EVP_PKEY_CTX_free(pctx);
    }

    void gen_keys(){
        EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(params_, NULL);

        if(!EVP_PKEY_keygen_init(key_ctx)){
            EXIT_WITH_MSG("Can't init keygen");
        }
        
        /* Generate the key */
        if (!EVP_PKEY_keygen(key_ctx, &ec_key_)){ 
            EXIT_WITH_MSG("Can't generate keys");
        }

        EVP_PKEY_CTX_free(key_ctx);
    }

public:
    Wallet() : params_(NULL), ec_key_(NULL){}

    void SavePrivate(const std::string& filename) const{
        BIO* file = BIO_new_file((filename + ".pem").c_str(), "w");        

        int len = PEM_write_bio_PrivateKey(file, ec_key_, NULL, NULL, 0, NULL, NULL);
        if (len <= 0) {
            EXIT_WITH_MSG("Could not write the private key");
        }

        BIO_free(file);
    }

    void LoadPrivate(const std::string& filename){
        BIO* file = BIO_new_file((filename + ".pem").c_str(), "r");

        ec_key_ = PEM_read_bio_PrivateKey(file, NULL, NULL, NULL); 
        if (!ec_key_){
            throw std::invalid_argument("Can't read keys");
        }

        BIO_free(file);
    }

    void GenKeys(){
        gen_key_params();
        gen_keys();        
    }

    EC_Sign SignMessage(const ByteMessage& msg) const{
        EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
        
        if(!(mdctx)) {
            EXIT_WITH_MSG("Can't create signing context");
        }
 
        if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_key_)){ 
            EXIT_WITH_MSG("Can't init sign operation");
        }
 
        if(1 != EVP_DigestSignUpdate(mdctx, msg.data(), msg.size())){
             EXIT_WITH_MSG("Can't sign message");
        }
 
        EC_Sign sig_res;
        size_t size_sig;

        if(1 != EVP_DigestSignFinal(mdctx, NULL, &size_sig)){
            EXIT_WITH_MSG("Can't retrieve size signature");
        }

        sig_res.resize(size_sig);
        if(1 != EVP_DigestSignFinal(mdctx, sig_res.data(), &size_sig)){
            EXIT_WITH_MSG("Can't retrieve signatures");
        }       

        EVP_MD_CTX_destroy(mdctx);
        return sig_res;
    }

    PrivateKey GetPrivateKey() const{
        PrivateKey res;
        size_t priv_key_len = 0;
        if (!EVP_PKEY_get_raw_private_key(ec_key_, NULL, &priv_key_len)){
            EXIT_WITH_MSG("Can't get length private key");;                        
        }

        res.resize(priv_key_len);

        if(!EVP_PKEY_get_raw_private_key(ec_key_, res.data(), &priv_key_len)){
            EXIT_WITH_MSG("Can't get raw private key");
        }

        return res;
    }

    PublicKey GetPublicKey() const{
        PublicKey res;
        size_t pub_key_len = 0;
        if (!EVP_PKEY_get_raw_public_key(ec_key_, NULL, &pub_key_len)){
            std::cerr << pub_key_len << std::endl;
            EXIT_WITH_MSG("Can't get length public key");
        }

        res.resize(pub_key_len);

        if(!EVP_PKEY_get_raw_public_key(ec_key_, res.data(), &pub_key_len)){
            EXIT_WITH_MSG("Can't get raw public key");
        }

        return res;
    }        
};