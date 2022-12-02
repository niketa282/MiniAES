#include "mini-aes.h"
#include <cmath>

int miniAES::MiniAES::bitCount(unsigned int n) {
 return (int)log2(n)+1;
}

std::tuple<unsigned, unsigned, unsigned> miniAES::MiniAES::round_key_generator (unsigned secret_key){
    if (bitCount(secret_key) > 16) {
      return {0, 0, 0}; // if key size greater than 16 bits we get no round keys generated 
    }
       
    return {0, 0, secret_key};
}


