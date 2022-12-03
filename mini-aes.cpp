#include "mini-aes.h"
#include <cmath>

int miniAES::MiniAES::bit_count(unsigned const& n) {
 return (int)log2(n)+1;
}

std::unordered_map<unsigned, unsigned>::iterator miniAES::MiniAES::nibble_sub(unsigned const& nibble) {
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

std::tuple<unsigned, unsigned, unsigned, unsigned> miniAES::MiniAES::shift_row(std::tuple<unsigned, unsigned, unsigned, unsigned>& nibbles) {
  auto [w0, w1, w2, w3] = nibbles;
  auto tmp = w1;
  w1 = w3;
  w3 = tmp;
  return {w0, w1, w2, w3};
}

std::tuple<unsigned, unsigned, unsigned, unsigned> miniAES::MiniAES::extract_key_nibbles(unsigned secret_key){
  unsigned w0 = secret_key >> kbitshiftw0;
  unsigned w1 = (secret_key >> kbitshiftw1) & kandval;
  unsigned w2 = (secret_key >> kbitshiftw2) & kandval;
  unsigned w3 = (secret_key & kandval); 
  return {w0, w1, w2, w3};
}

unsigned miniAES::MiniAES::concatanate_key_nibbles(std::tuple<unsigned, unsigned, unsigned, unsigned>& nibbles) {
  auto [w4, w5, w6, w7] = nibbles;
  return (w4 << kbitshiftw0) | (w5 << kbitshiftw1) | (w6 << kbitshiftw2) | (w7);
}

std::tuple<unsigned, unsigned, unsigned> miniAES::MiniAES::round_key_generator(unsigned secret_key){
  if (bit_count(secret_key) > 16) {
    return {0, 0, 0}; // if key size greater than 16 bits we get no round keys generated 
  } 
  auto [w0, w1, w2, w3] = extract_key_nibbles(secret_key);
 
  unsigned w4 = w0 ^ ((nibble_sub(w3))->second) ^ rcon1;
  unsigned w5 = w1 ^ w4;
  unsigned w6 = w2 ^ w5;
  unsigned w7 = w3 ^ w6;
  std::tuple<unsigned, unsigned, unsigned, unsigned> values_to_concatanate_r1 = {w4, w5, w6, w7};

  unsigned w8 = w4 ^ ((nibble_sub(w7))->second) ^ rcon2;
  unsigned w9 = w5 ^ w8;
  unsigned w10 = w6 ^ w9;
  unsigned w11 = w7 ^ w10;
  std::tuple<unsigned, unsigned, unsigned, unsigned> values_to_concatanate_r2 = {w8, w9, w10, w11};
  return {concatanate_key_nibbles(values_to_concatanate_r2), concatanate_key_nibbles(values_to_concatanate_r1), secret_key};
}

unsigned miniAES::MiniAES::encryption(unsigned plaintext, unsigned secret_key) {
 unsigned round = 0;
 unsigned concatanateresult = 0;
 while(round < MAX_ROUNDS) {
  auto k0 = std::get<2>(round_key_generator(secret_key));
  auto keyaddition = plaintext ^ k0;
  ++round;
  auto [w0, w1, w2, w3] = extract_key_nibbles(keyaddition);
  unsigned nibble_sub_w0 = (nibble_sub(w0))->second;
  unsigned nibble_sub_w1 = (nibble_sub(w1))->second;
  unsigned nibble_sub_w2 = (nibble_sub(w2))->second;
  unsigned nibble_sub_w3 = (nibble_sub(w3))->second;
  std::tuple<unsigned, unsigned, unsigned, unsigned> nibble_sub_output = {nibble_sub_w0, nibble_sub_w1, nibble_sub_w2, nibble_sub_w3};
  concatanateresult = concatanate_key_nibbles(nibble_sub_output);
  ++round;
 }
 return concatanateresult; // TO FIX
}


