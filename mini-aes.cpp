#include "mini-aes.h"
#include <cmath>

int miniAES::MiniAES::bit_count(unsigned int n) {
 return (int)log2(n)+1;
}

std::map<unsigned, unsigned>::iterator miniAES::MiniAES::nibble_sub(unsigned nibble) {
  substitution_table[0b0000] = 0b1110;
  substitution_table[0b0001] = 0b0100;
  substitution_table[0b0010] = 0b1101;
  substitution_table[0b0011] = 0b0001;
  substitution_table[0b0100] = 0b0010;
  substitution_table[0b0101] = 0b1111;
  substitution_table[0b0110] = 0b1011;
  substitution_table[0b0111] = 0b1000;
  substitution_table[0b1000] = 0b0011;
  substitution_table[0b1001] = 0b1010;
  substitution_table[0b1010] = 0b0110;
  substitution_table[0b1011] = 0b1100;
  substitution_table[0b1100] = 0b0101;
  substitution_table[0b1101] = 0b1001;
  substitution_table[0b1110] = 0b0000;
  substitution_table[0b1111] = 0b0111;

  // find desired nibble
  it = substitution_table.find(nibble);
  return it;
}

std::tuple<unsigned, unsigned, unsigned, unsigned> miniAES::MiniAES::extract_key_nibbles(unsigned secret_key){
  unsigned w0 = secret_key  >> kbitshiftw0;
  unsigned w1 = (secret_key >> kbitshiftw1) & kandval;
  unsigned w2 = (secret_key >> kbitshiftw2) & kandval;
  unsigned w3 = (secret_key & kandval); 
  return {w0, w1, w2, w3};
}

std::tuple<unsigned, unsigned, unsigned> miniAES::MiniAES::round_key_generator(unsigned secret_key){
  if (bit_count(secret_key) > 16) {
    return {0, 0, 0}; // if key size greater than 16 bits we get no round keys generated 
  } 
   
  return {0, 0, secret_key};
}


