#ifndef MINI_AES_H
#define MINI_AES_H

#include <tuple>
#include <unordered_map>
#include <array>
#include <iostream>
namespace miniAES{

constexpr unsigned kmaxsize = 16;
constexpr unsigned kbitshiftw0 = 12;
constexpr unsigned kbitshiftw1 = 8;
constexpr unsigned kbitshiftw2 = 4;
constexpr unsigned kandval = 0x0F;
constexpr unsigned rcon1 = 0b0001;
constexpr unsigned rcon2 = 0b0010;
constexpr unsigned MAX_ROUNDS = 1;
class MiniAES {
 public:
  std::tuple<unsigned, unsigned, unsigned, unsigned> extract_key_nibbles(unsigned secret_key);
  unsigned concatanate_key_nibbles(std::tuple<unsigned, unsigned, unsigned, unsigned>& nibbles);
  std::tuple<unsigned, unsigned, unsigned> round_key_generator(unsigned secret_key);
  int bit_count(unsigned const& n);
  std::unordered_map<unsigned, unsigned>::iterator nibble_sub(unsigned const& nibble);
  std::tuple<unsigned, unsigned, unsigned, unsigned> shift_row(std::tuple<unsigned, unsigned, unsigned, unsigned>& nibbles);
  unsigned encryption(unsigned plaintext, unsigned secret_key);
  unsigned mix_column(std::tuple<unsigned, unsigned, unsigned, unsigned>& nibbles);
  unsigned key_addition(unsigned plain_text, unsigned secret_key);
 private:
  std::unordered_map<unsigned, unsigned> substitution_table{};
  std::unordered_map<unsigned, unsigned>::iterator it{};
  std::tuple<unsigned, unsigned, unsigned, unsigned> nibble_bits{};
  std::tuple<unsigned, unsigned, unsigned, unsigned> k2{};
  std::tuple<unsigned, unsigned, unsigned, unsigned> k1{};
  unsigned k0 = 0;
  unsigned bitcount = 0;
  unsigned Keyaddition = 0;
};

}  // namespace miniAES

#endif // MINI_AES_H

