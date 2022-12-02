#include <gtest/gtest.h>
#include "mini-aes.h"

TEST(BitCounterTest, CountNumbBits)
{
   miniAES::MiniAES obj{};
   int count_numb_bits = obj.bitCount(0b1100001111110000);
   EXPECT_EQ(16, count_numb_bits);
}

TEST(MiniAesTest, HandleRoundKeyGeneration)
{
   miniAES::MiniAES obj{};
   // testing round key generation for round 1 ie k0
   auto keys = obj.round_key_generator(0b1100001111110000); 
   EXPECT_EQ(0b1100001111110000, std::get<2>(keys));

   // testing round key generation for secret key greater than 16 bits
   keys = obj.round_key_generator(0b10000001111101000);
   EXPECT_EQ(0, std::get<0>(keys));
   EXPECT_EQ(0, std::get<1>(keys));
   EXPECT_EQ(0, std::get<2>(keys));
}

