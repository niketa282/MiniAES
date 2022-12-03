#include <gtest/gtest.h>
#include "mini-aes.h"

TEST(BitCounterTest, CountNumbBits)
{
   miniAES::MiniAES obj{};
   int count_numb_bits = obj.bit_count(0b1100001111110000);
   EXPECT_EQ(16, count_numb_bits);
}

TEST(MiniAesTest, ExtractNibblesFunciton)
{
   miniAES::MiniAES obj{};
   auto keys = obj.extract_key_nibbles(0b1100001111110000); 
   // check nibble w0
   EXPECT_EQ(0b1100, std::get<0>(keys));
   // check nibble w1
   EXPECT_EQ(0b0011, std::get<1>(keys));
   // check nibble w2
   EXPECT_EQ(0b1111, std::get<2>(keys));
   // check nibble w3
   EXPECT_EQ(0b0000, std::get<3>(keys));
}

TEST(MiniAesTest, HandleRoundKeyGeneration)
{
   miniAES::MiniAES obj{};
   // testing round key generation for round 0 ie k0
   auto keys = obj.round_key_generator(0b1100001111110000); 
   EXPECT_EQ(0b1100001111110000, std::get<2>(keys));
   
   // testing round key generation for round 1 ie k1
   EXPECT_EQ(0b0011000011111111, std::get<1>(keys));

   // testing round key generation for round 2 ie k2
   EXPECT_EQ(0b0110011010010110, std::get<0>(keys));

   // testing round key generation for secret key greater than 16 bits
   keys = obj.round_key_generator(0b10000001111101000);
   EXPECT_EQ(0, std::get<0>(keys));
   EXPECT_EQ(0, std::get<1>(keys));
   EXPECT_EQ(0, std::get<2>(keys));
}

TEST(MiniAesTest, NibleSubFunction)
{
   miniAES::MiniAES obj{};
   //testing input returns desired output via key and values using std::map data structure
   std::unordered_map<unsigned, unsigned>::iterator result = obj.nibble_sub(0b0000);
   EXPECT_EQ(0b1110, result->second);
   result = obj.nibble_sub(0b1111);
   EXPECT_EQ(0b0111, result->second);
   result = obj.nibble_sub(0b1010);
   EXPECT_EQ(0b0110, result->second);
}

