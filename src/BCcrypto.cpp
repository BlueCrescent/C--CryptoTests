/*
 * Decoder1.cpp
 *
 *  Created on: 13.04.2014
 *      Author: timm
 */

#include "BCcrypto.h"

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/secblock.h"

#include <cstring>
#include <cassert>

namespace BCcrypto {

  void cbcEncodeAes(const byte * plain_text, const unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte iv[], byte * OUT_iv_cipher_text) {
    memcpy(OUT_iv_cipher_text, iv, IV_SIZE);
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(key, key.size(), iv);

    cbcEncryption.ProcessData((OUT_iv_cipher_text + IV_SIZE), plain_text, length);
  }

  void cbcDecodeAes(const byte * iv_cipher_text, const unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte * OUT_plain_text) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbcEncryption(key, key.size(), iv_cipher_text);
    cbcEncryption.ProcessData((OUT_plain_text), (iv_cipher_text + IV_SIZE), length - IV_SIZE);
  }

  void ctrEncodeAes(const byte * plain_text, const unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte iv[], byte * OUT_iv_cipher_text) {
    memcpy(OUT_iv_cipher_text, iv, IV_SIZE);
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption ctrEncryption(key, key.size(), iv);

    ctrEncryption.ProcessData((OUT_iv_cipher_text + IV_SIZE), plain_text, length);
  }

  void ctrDecodeAes(const byte * iv_cipher_text, const unsigned int length,
                    const CryptoPP::SecByteBlock & key, byte * OUT_plain_text) {
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption ctrEncryption(key, key.size(), iv_cipher_text);
    ctrEncryption.ProcessData((OUT_plain_text), (iv_cipher_text + IV_SIZE), length - IV_SIZE);
  }

}
