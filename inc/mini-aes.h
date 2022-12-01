#ifndef MINI_AES_H
#define MINI_AES_H

#include <tuple>
namespace miniAES{
    std::tuple<unsigned, unsigned, unsigned>round_key_generator (unsigned secret_key);
}

#endif // MINI_AES_H