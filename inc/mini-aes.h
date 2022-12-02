#ifndef MINI_AES_H
#define MINI_AES_H

#include <tuple>
namespace miniAES{
class MiniAES {
public:
    std::tuple<unsigned, unsigned, unsigned>round_key_generator (unsigned secret_key);
    int bitCount(unsigned n);
};

}  // namespace miniAES

#endif // MINI_AES_H

