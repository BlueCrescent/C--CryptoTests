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

#include "cryptopp/osrng.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/secblock.h"

#include "cryptopp/hex.h"

// Source by berkay @ http://stackoverflow.com/questions/12306956/example-of-aes-using-crypto

int main() {

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
