/*!
    \file main.cpp
*/

#include "wallet.h"
#include "crypto.h"
#include <iostream>
#include <iomanip>

using namespace std;


int main(int argc, char* argv[]) {	
	
	Crypto cr;
    vector<uint8_t> msg = {0xFF, 0xFF, 0xFF};    
    SHA256_Digest dig = cr.GenDigest(msg);

    for(auto val : dig){
        cout << hex << val + 0;
    }

    cout << endl;

	return 0;
}