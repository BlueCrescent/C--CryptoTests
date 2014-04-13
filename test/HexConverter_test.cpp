/*
 * HexConverter_test.cpp
 *
 *  Created on: 12.04.2014
 *      Author: timm
 */

#include "HexConverter.h"

#include "gtest/gtest.h"

#include <string>

class HexConverterTest : public ::testing::Test {
protected:
//  virtual void SetUp() {}

//  virtual void TearDown() {}

};

void assertRightConversionToHex(std::string input, std::string expected_output) {
  ASSERT_EQ(HexConverter::toHex(input), expected_output);
}

TEST_F(HexConverterTest, ConvertEmptyStringToHexShouldReturnEmptyString) {
  assertRightConversionToHex(std::string(""), std::string(""));
}

TEST_F(HexConverterTest, ConvertSimpleStringToHex) {
  assertRightConversionToHex(std::string("a"), std::string("61"));
}

TEST_F(HexConverterTest, ConvertSimpleStringWithMoreThanOneCharToHex) {
  assertRightConversionToHex(std::string("aA k"), std::string("6141206b"));
}

TEST_F(HexConverterTest, ConvertEmptyHexStringToCharShouldReturnEmptyString) {
  const std::string input("");
  std::string expected_output = std::string("");
  ASSERT_EQ(HexConverter::toChar(input), expected_output);
}

TEST_F(HexConverterTest, ConvertSimpleHexStringToCharShouldReturnEmptyString) {
  const std::string input("61");
  std::string expected_output = std::string("a");
  ASSERT_EQ(HexConverter::toChar(input), expected_output);
}

TEST_F(HexConverterTest, ConvertSimpleHexStringWithMoreThanOneCharToChar) {
  const std::string input("6141206b");
  std::string expected_output = std::string("aA k");
  ASSERT_EQ(HexConverter::toChar(input), expected_output);
}

TEST_F(HexConverterTest, ExpectInvalidHexStringExeptionIfStringLengthNotEven) {
  const std::string input("6141206");
  ASSERT_THROW(HexConverter::toChar(input), HexConverter::HexStringWithoutEvenLengthException *);
}
