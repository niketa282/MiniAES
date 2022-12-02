#ifndef MINI_AES_H
#define MINI_AES_H

#include <tuple>
#include <map>
namespace miniAES{
class MiniAES {
public:
    std::tuple<unsigned, unsigned, unsigned>round_key_generator(unsigned secret_key);
    int bit_count(unsigned n);
    std::map<unsigned, unsigned>::iterator nibble_sub(unsigned nibble);
private:
  std::map<unsigned, unsigned> substitution_table;
  std::map<unsigned, unsigned>::iterator it;
};

}  // namespace miniAES

#endif // MINI_AES_H

