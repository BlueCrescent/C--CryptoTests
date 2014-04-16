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

//  void readIv(const char * iv_cipher_text, byte OUT_iv[]);
//
//  void removeIv(const char * iv_cipher_text, unsigned int length, char * OUT_cipher_text);

  void cbcEncodeAes(const byte * plain_text, unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte iv[], byte * OUT_iv_cipher_text);

  void cbcDecodeAes(const byte * iv_cipher_text, unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte * OUT_plain_text);

  void ctrEncodeAes(const byte * plain_text, unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte iv[], byte * OUT_iv_cipher_text);

  void ctrDecodeAes(const byte * iv_cipher_text, unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte * OUT_plain_text);
};

#endif /* DECODER1_H_ */
