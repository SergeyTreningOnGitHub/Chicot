#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

class Wallet{
public:
    void Init(){
        ERR_load_crypto_strings();
    }
};