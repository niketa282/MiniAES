#include <gtest/gtest.h>
#include "mini-aes.h"

TEST(MiniAesTest, HandleRoundKeyGeneration)
{
   auto keys = miniAES::round_key_generator(0b1100001111110000); 
   EXPECT_EQ(0b1100001111110000, std::get<2>(keys));
}