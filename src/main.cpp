/*
 * test.cpp
 *
 *  Created on: 12.04.2014
 *      Author: timm
 */

#include <iostream>
#include <iomanip>

//#include "cryptopp/modes.h"
//#include "cryptopp/aes.h"
//#include "cryptopp/filters.h"

//#include "cryptopp/osrng.h"
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "cryptopp/cryptlib.h"
//#include "cryptopp/secblock.h"
//
//#include "cryptopp/hex.h"

// Source by berkay @ http://stackoverflow.com/questions/12306956/example-of-aes-using-crypto

#include <string>
#include <iostream>

#include "HexConverter.h"
#include "BCcrypto.h"

int main() {

  std::string cbc_k1 = HexConverter::toChar(std::string("140b41b22a29beb4061bda66b6747e14"));
  std::string cbc_ct1 = HexConverter::toChar(std::string("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"));

  const CryptoPP::SecByteBlock cbc_k1_block((byte *) cbc_k1.c_str(), cbc_k1.size());

//  const char cbc_k1[] = "140b41b22a29beb4061bda66b6747e14";
//  const char cbc_ct1[] = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
//  const CryptoPP::SecByteBlock cbc_k1_block((byte *) cbc_k1, sizeof(cbc_k1));

  char cbc_pt1[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  BCcrypto::cbcDecodeAes((byte *) cbc_ct1.c_str(), cbc_ct1.size(), cbc_k1_block, (byte *) cbc_pt1);

  std::cout << "Plain text 1: " << cbc_pt1 << std::endl;
  /////////////////////////////////////////////////////////////////
  std::string cbc_k2 = HexConverter::toChar(std::string("140b41b22a29beb4061bda66b6747e14"));
  std::string cbc_ct2 = HexConverter::toChar(std::string("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"));
  const CryptoPP::SecByteBlock cbc_k2_block((byte *) cbc_k2.c_str(), cbc_k2.size());
  char cbc_pt2[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  BCcrypto::cbcDecodeAes((byte *) cbc_ct2.c_str(), cbc_ct2.size(), cbc_k2_block, (byte *) cbc_pt2);
  std::cout << "Plain text 2: " << cbc_pt2 << std::endl;
  /////////////////////////////////////////////////////////////////
  std::string ctr_k1 = HexConverter::toChar(std::string("36f18357be4dbd77f050515c73fcf9f2"));
  std::string ctr_ct1 = HexConverter::toChar(std::string("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"));
  const CryptoPP::SecByteBlock ctr_k1_block((byte *) ctr_k1.c_str(), ctr_k1.size());
  char ctr_pt1[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  BCcrypto::ctrDecodeAes((byte *) ctr_ct1.c_str(), ctr_ct1.size(), ctr_k1_block, (byte *) ctr_pt1);
  std::cout << "Plain text 3: " << ctr_pt1 << std::endl;
  /////////////////////////////////////////////////////////////////
  std::string ctr_k2 = HexConverter::toChar(std::string("36f18357be4dbd77f050515c73fcf9f2"));
  std::string ctr_ct2 = HexConverter::toChar(std::string("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"));
  const CryptoPP::SecByteBlock ctr_k2_block((byte *) ctr_k2.c_str(), ctr_k2.size());
  char ctr_pt2[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  BCcrypto::ctrDecodeAes((byte *) ctr_ct2.c_str(), ctr_ct2.size(), ctr_k2_block, (byte *) ctr_pt2);
  std::cout << "Plain text 4: " << ctr_pt2 << std::endl;


//  std::cout << "Plain text 1: " << HexConverter::toChar2(cbc_pt1) << std::endl;

//  CryptoPP::HexDecoder hexDecoder;

//  const byte cipherText[] = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";

//  CryptoPP::AutoSeededRandomPool rnd_pool;
//
//  // Generate a random key
//  CryptoPP::SecByteBlock key(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
//  rnd_pool.GenerateBlock((byte * ) key, key.size());
//
//  // Generate a random IV
//  byte iv[CryptoPP::AES::BLOCKSIZE];
//  rnd_pool.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
//
//  char plainText[] = "Hello! How are you.";
//  int messageLen = (int)strlen(plainText) + 1;
//
//  std::cout << "PT: " << plainText << std::endl;
//
//  //////////////////////////////////////////////////////////////////////////
//  // Encrypt
//
//  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfbEncryption(key, key.size(), iv);
//  cfbEncryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);
//
//  std::cout << "CT: " << plainText << std::endl;
//
//  //////////////////////////////////////////////////////////////////////////
//  // Decrypt
//
//  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cfbDecryption(key, key.size(), iv);
//  cfbDecryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);
//
//  std::cout << "PT: " << plainText << std::endl << std::endl;

//  // Key and IV setup
//  //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
//  //bit). This key is secretly exchanged between two parties before communication
//  //begins. DEFAULT_KEYLENGTH= 16 bytes
//  byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
//  memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
//  memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
//
//  //
//  // String and Sink setup
//  //
//  std::string plaintext = "Now is the time for all good men to come to the aide...";
//  std::string ciphertext;
//  std::string decryptedtext;
//
//  //
//  // Dump Plain Text
//  //
//  std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
//  std::cout << plaintext;
//  std::cout << std::endl << std::endl;
//
//  //
//  // Create Cipher Text
//  //
//  CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
//  CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );
//
//  CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
//  stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
//  stfEncryptor.MessageEnd();
//
//  //
//  // Dump Cipher Text
//  //
//  std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
//
//  for(unsigned int i = 0; i < ciphertext.size(); ++i) {
//
//      std::cout << "0x" << std::hex << (0xFF & static_cast<byte>(ciphertext[i])) << " ";
//  }
//
//  std::cout << std::endl << std::endl;
//
//  //
//  // Decrypt
//  //
//  CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
//  CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );
//
//  CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
//  stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
//  stfDecryptor.MessageEnd();
//
//  //
//  // Dump Decrypted Text
//  //
//  std::cout << "Decrypted Text: " << std::endl;
//  std::cout << decryptedtext;
//  std::cout << std::endl << std::endl;
  return 0;
}
