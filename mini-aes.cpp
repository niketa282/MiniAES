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

unsigned miniAES::MiniAES::mix_column(std::tuple<unsigned, unsigned, unsigned, unsigned>& nibbles) {
  auto constant_matrix = std::make_tuple(0b0011u, 0b0010u, 0b0010u, 0b0011u);
  auto [w0, w1, w2, w3] = nibbles;
  auto [w4, w5, w6, w7] = constant_matrix;
  
  std::array<std::array<unsigned, 16>, 16> lookup_table={{
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {0,2,4,6,8,10,12,14,3,1,7,5,11,9,15,13},
    {0,3,6,5,12,15,10,9,11,8,13,14,7,4,1,2},
    {0,4,8,12,3,7,11,15,6,2,14,10,5,1,13,9},
    {0,5,10,15,7,2,13,8,14,11,4,1,9,12,3,6},
    {0,6,12,10,11,13,7,1,5,3,9,15,14,8,2,4},
    {0,7,14,9,15,8,1,6,13,10,3,4,2,5,12,11},
    {0,8,3,11,6,14,5,13,12,4,15,7,10,2,9,1},
    {0,9,1,8,2,11,3,10,4,13,5,12,6,15,7,14},
    {0,10,7,13,14,4,9,3,15,5,8,2,1,11,6,12},
    {0,11,5,14,10,1,15,4,7,12,2,9,13,6,8,3},
    {0,12,11,7,5,9,14,2,10,6,1,13,15,3,4,8},
    {0,13,9,4,1,12,8,5,2,15,11,6,3,14,10,7},
    {0,14,15,1,13,3,2,12,9,7,6,8,4,10,11,5},
    {0,15,13,2,9,6,4,8,1,14,12,3,8,7,5,10}
  }};

   auto val1 = lookup_table[w4][w0];
   auto val2 = lookup_table[w6][w1];
   auto val3 = lookup_table[w5][w0];
   auto val4 = lookup_table[w7][w1];
   auto upperone = val1 ^ val2; // 0000
   auto lowerone = val3 ^ val4; // 1110

   auto val5 = lookup_table[w4][w2];
   auto val6 = lookup_table[w6][w3];
   auto val7 = lookup_table[w5][w2];
   auto val8 = lookup_table[w7][w3];
   auto upperone1 = val5 ^ val6; // 0011
   auto lowerone1 = val7 ^ val8; // 1110

   auto concatanate_value = std::make_tuple(upperone, lowerone, upperone1, lowerone1);
   return concatanate_key_nibbles(concatanate_value);
}

std::tuple<unsigned, unsigned, unsigned> miniAES::MiniAES::round_key_generator(unsigned secret_key){
  if (bit_count(secret_key) > kmaxsize) {
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


