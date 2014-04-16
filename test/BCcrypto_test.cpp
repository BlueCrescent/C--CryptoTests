/*
 * Decoder1_test.cpp
 *
 *  Created on: 13.04.2014
 *      Author: timm
 */

#include "BCcrypto.h"

#include "gtest/gtest.h"

#include "cryptopp/osrng.h"
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"

#include <iostream>

class CBcrptoTests : public ::testing::Test {
protected:
  virtual void SetUp() {
    // Generate a random key
    key = CryptoPP::SecByteBlock(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
    rnd_pool.GenerateBlock((byte * ) key, key.size());
    key_string += std::string((char *) key.begin(), key.size());
    ASSERT_EQ(key_string.size(), key.size());
    ASSERT_EQ((unsigned int) BCcrypto::IV_SIZE, key.size());
    // Generate a random IV
    rnd_pool.GenerateBlock(iv, BCcrypto::IV_SIZE);
  }

//  virtual void TearDown() {}

  CryptoPP::AutoSeededRandomPool rnd_pool;
  CryptoPP::SecByteBlock key;
  std::string key_string;
  byte iv[CryptoPP::AES::BLOCKSIZE];
};

TEST_F(CBcrptoTests, EncryptedTextShouldHaveSameLengthPlusIVLength) {
  std::string plainText("Hello crypto world!");
  std::string cipherText = BCcrypto::cbcEncodeAes(plainText, key, iv);
  ASSERT_EQ(plainText.size(), cipherText.size() - BCcrypto::IV_SIZE);
}

TEST_F(CBcrptoTests, EncryptDecryptTest) {
  std::string plainText("Hello crypto world!");
  std::string cipherText = BCcrypto::cbcEncodeAes(plainText, key, iv);
  std::string decryptedText = BCcrypto::cbcDecodeAes(cipherText, key_string);
  ASSERT_STREQ(plainText.c_str(), decryptedText.c_str());
}
