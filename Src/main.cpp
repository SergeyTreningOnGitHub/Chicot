/*!
    \file main.cpp
*/

#include "wallet.h"
#include <iostream>
#include <iomanip>

using namespace std;


int main(int argc, char* argv[]) {	
	
	Wallet wallet;
    try{
        wallet.LoadPrivate("private");
        cout << "Private is loaded" << endl;
    }catch(const invalid_argument& ex){
        wallet.GenKeys();
        wallet.SavePrivate("private");
        cout << "Private is generated" << endl;
    }

    ByteMessage mess = {0xFF, 0xFF, 0xFF};
    EC_Sign sign = wallet.SignMessage(mess);

    cout << "Message is signed" << endl;
    PublicKey pub_key = wallet.GetPublicKey();

    bool is_verified = VerifySign(mess, sign, pub_key);
    if(is_verified)
        cout << "Verification success" << endl;
    else
        cout << "Verification error" << endl;

    mess[0] = 0xAA;

    is_verified = VerifySign(mess, sign, pub_key);
    if(is_verified)
        cout << "Verification forbidden message success" << endl;
    else
        cout << "Verification forbidden message error" << endl;

	return 0;
}