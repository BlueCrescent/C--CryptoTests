/*
 * Decoder1.h
 *
 *  Created on: 13.04.2014
 *      Author: timm
 */

#ifndef DECODER1_H_
#define DECODER1_H_

#include <string>

#include "cryptopp/secblock.h"
#include "cryptopp/aes.h"

namespace BCcrypto {

  const int IV_SIZE = CryptoPP::AES::BLOCKSIZE;

  std::string readIv(const std::string & cipher_text);

  std::string removeIv(const std::string & cipher_text);

  std::string cbcEncodeAes(const std::string & plain_text, const CryptoPP::SecByteBlock & key, byte iv[]);

  std::string cbcDecodeAes(const std::string & iv_cipher_text, const std::string & key);
};

#endif /* DECODER1_H_ */
