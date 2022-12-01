#include <gtest/gtest.h>
#include "mini-aes.h"

TEST(Calculator, Add)
{
  EXPECT_EQ(5, miniAES::add(2, 3));
}