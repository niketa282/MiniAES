#ifndef MINI_AES_H
#define MINI_AES_H

#include <tuple>
#include <unordered_map>
namespace miniAES{

constexpr unsigned kbitshiftw0 = 12;
constexpr unsigned kbitshiftw1 = 8;
constexpr unsigned kbitshiftw2 = 4;
constexpr unsigned kandval = 0x0F;
constexpr unsigned rcon1 = 0b0001;
constexpr unsigned rcon2 = 0b0010;
class MiniAES {
 public:
  std::tuple<unsigned, unsigned, unsigned, unsigned> extract_key_nibbles(unsigned secret_key);
  unsigned concatanate_key_nibbles(std::tuple<unsigned, unsigned, unsigned, unsigned>& nibbles);
  std::tuple<unsigned, unsigned, unsigned> round_key_generator(unsigned secret_key);
  int bit_count(unsigned const& n);
  std::unordered_map<unsigned, unsigned>::iterator nibble_sub(unsigned const& nibble);
 private:
  std::unordered_map<unsigned, unsigned> substitution_table;
  std::unordered_map<unsigned, unsigned>::iterator it;
};

}  // namespace miniAES

#endif // MINI_AES_H

