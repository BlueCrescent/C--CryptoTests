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

void assertCorrectConversionToHex(std::string input, std::string expected_output) {
  ASSERT_EQ(HexConverter::toHex(input), expected_output);
}

void assertCorrectConversionToChar(std::string input, std::string expected_output) {
  ASSERT_EQ(HexConverter::toChar(input), expected_output);
}

void assertCorrectConversionToChar2(std::string input, std::string expected_output) {
  ASSERT_EQ(HexConverter::toChar2(input), expected_output);
}

TEST_F(HexConverterTest, ConvertEmptyStringToHexShouldReturnEmptyString) {
  assertCorrectConversionToHex(std::string(""), std::string(""));
}

TEST_F(HexConverterTest, ConvertSimpleStringToHex) {
  assertCorrectConversionToHex(std::string("a"), std::string("61"));
}

TEST_F(HexConverterTest, ConvertSimpleStringWithMoreThanOneCharToHex) {
  assertCorrectConversionToHex(std::string("aA k"), std::string("6141206b"));
}

TEST_F(HexConverterTest, ConvertEmptyHexStringToCharShouldReturnEmptyString) {
  assertCorrectConversionToChar(std::string(""), std::string(""));
}

TEST_F(HexConverterTest, ConvertSimpleHexStringToCharReturnCheck) {
  assertCorrectConversionToChar(std::string("61"), std::string("a"));
}

TEST_F(HexConverterTest, ConvertSimpleHexStringWithMoreThanOneCharToChar) {
  assertCorrectConversionToChar(std::string("6141206b"), std::string("aA k"));
}

TEST_F(HexConverterTest, ExpectInvalidHexStringExeptionIfStringLengthNotEven) {
  const std::string input("6141206");
  ASSERT_THROW(HexConverter::toChar(input), HexConverter::HexStringWithoutEvenLengthException *);
}

TEST_F(HexConverterTest, ConvertEmptyHexStringToChar2ShouldReturnEmptyString) {
  assertCorrectConversionToChar2(std::string(""), std::string(""));
}

TEST_F(HexConverterTest, ConvertSimpleHexStringToChar2ReturnCheck) {
  assertCorrectConversionToChar2(std::string("61"), std::string("a"));
}

TEST_F(HexConverterTest, ConvertSimpleHexStringWithMoreThanOneCharToChar2) {
  assertCorrectConversionToChar2(std::string("6141206b"), std::string("aA k"));
}

TEST_F(HexConverterTest, ExpectInvalidHexStringExeptionIfStringLengthNotEven2) {
  const std::string input("6141206");
  ASSERT_THROW(HexConverter::toChar2(input), HexConverter::HexStringWithoutEvenLengthException *);
}

TEST_F(HexConverterTest, ConversionsAreInverse) {
  const std::string input("6141206b");
  const std::string charText = HexConverter::toChar(input);
  assertCorrectConversionToHex(charText, input);
}

TEST_F(HexConverterTest, ConversionsAreInverse2) {
  const std::string input("6141206b");
  const std::string charText = HexConverter::toChar2(input);
  assertCorrectConversionToHex(charText, input);
}
