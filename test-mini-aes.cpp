#include <gtest/gtest.h>
#include "mini-aes.h"

TEST(MiniAesTest, CountNumbBits)
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

TEST(MiniAesTest, ShiftRow)
{
   miniAES::MiniAES obj{};
   std::tuple<unsigned, unsigned, unsigned, unsigned> result = obj.extract_key_nibbles(0b1111011110100001);
   EXPECT_EQ(0b1111, std::get<0>(obj.shift_row(result)));
   EXPECT_EQ(0b0001, std::get<1>(obj.shift_row(result)));
   EXPECT_EQ(0b1010, std::get<2>(obj.shift_row(result)));
   EXPECT_EQ(0b0111, std::get<3>(obj.shift_row(result)));
}

TEST(MiniAesTest, ConcatanateKeyNibbles)
{
   miniAES::MiniAES obj{};
   std::tuple<unsigned, unsigned, unsigned, unsigned> result = obj.extract_key_nibbles(0b1111011110100001);
   EXPECT_EQ(0b1111011110100001, obj.concatenate_key_nibbles(result));
}

TEST(MiniAesTest, MixColumn)
{
   miniAES::MiniAES obj{};
   auto values = std::make_tuple(0b1111u, 0b0001u, 0b1010u, 0b0111u);
   EXPECT_EQ(0b0000111000111110, obj.mix_column(values));
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
   std::unordered_map<unsigned, unsigned>::iterator result = obj.nibble_sub_encyryption(0b0000);
   EXPECT_EQ(0b1110, result->second);
   result = obj.nibble_sub_encyryption(0b1111);
   EXPECT_EQ(0b0111, result->second);
   result = obj.nibble_sub_encyryption(0b1010);
   EXPECT_EQ(0b0110, result->second);
}

TEST(MiniAesTest, KeyAddition)
{
   miniAES::MiniAES obj{};
   auto keyAdditionResult = obj.key_addition(0b0000111000111110, 0b0011000011111111);
   EXPECT_EQ(0b0011111011000001, keyAdditionResult);
   keyAdditionResult = obj.key_addition(0b1001110001100011, 0b1100001111110000);
   EXPECT_EQ(0b0101111110010011, keyAdditionResult);
}

TEST(MiniAesTest, Encryptiontest)
{
   miniAES::MiniAES obj{};
   // plaintext = 0b1001110001100011 ciphertext = 0b0111001011000110 
   auto result = obj.encryption(0b1001110001100011, 0b1100001111110000);
   EXPECT_EQ(0b0111001011000110, result);
}

TEST(MiniAesTest, Decryptiontest)
{
   miniAES::MiniAES obj{};
   // plaintext = 0b1001110001100011 ciphertext = 0b0111001011000110 
   auto result = obj.decryption(0b0111001011000110, 0b1100001111110000);
   EXPECT_EQ(0b1001110001100011, result);
}


