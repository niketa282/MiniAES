#include "mini-aes.h"

std::tuple<unsigned, unsigned, unsigned> miniAES::round_key_generator (unsigned secret_key){
    return {0, 0, secret_key};
}