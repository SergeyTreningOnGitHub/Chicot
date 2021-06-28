#include "utils.h"
#include <iostream>
#include <cstdlib>

using namespace std;
void ExitWithMsg(const std::string& msg){
    cerr << msg << endl;
    exit(-1);
}