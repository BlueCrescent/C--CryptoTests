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

class BCcrptoTests : public ::testing::Test {
protected:
  virtual void SetUp() {
    // Generate a random key
    key = CryptoPP::SecByteBlock(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
    rnd_pool.GenerateBlock((byte * ) key, key.size());
//    key_string += std::string((char *) key.begin(), key.size());
//    ASSERT_EQ(key_string.size(), key.size());
//    ASSERT_EQ((unsigned int) BCcrypto::IV_SIZE, key.size());
    // Generate a random IV
    rnd_pool.GenerateBlock(iv, BCcrypto::IV_SIZE);
  }

//  virtual void TearDown() {}

  CryptoPP::AutoSeededRandomPool rnd_pool;
  CryptoPP::SecByteBlock key;
  std::string key_string;
  byte iv[CryptoPP::AES::BLOCKSIZE];
};


TEST_F(BCcrptoTests, CBCEncryptDecryptTest) {
  const char plain_text[] = "Hello crypto world!";
  char cipher_text[] =      "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  char decrypted_text[] =   "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  BCcrypto::cbcEncodeAes((byte *) plain_text, sizeof(plain_text), key, iv, (byte *) cipher_text);
  BCcrypto::cbcDecodeAes((byte *) cipher_text, sizeof(plain_text) + BCcrypto::IV_SIZE, key, (byte *) decrypted_text);
  ASSERT_STREQ(plain_text, decrypted_text);
}

TEST_F(BCcrptoTests, CTREncryptDecryptTest) {
  const char plain_text[] = "Hello crypto world!";
  char cipher_text[] =      "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  char decrypted_text[] =   "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
  BCcrypto::ctrEncodeAes((byte *) plain_text, sizeof(plain_text), key, iv, (byte *) cipher_text);
  BCcrypto::ctrDecodeAes((byte *) cipher_text, sizeof(plain_text) + BCcrypto::IV_SIZE, key, (byte *) decrypted_text);
  ASSERT_STREQ(plain_text, decrypted_text);
}
