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

  std::string readIv(const std::string& cipher_text) {
    return cipher_text.substr(0, IV_SIZE);
  }

  std::string removeIv(const std::string& cipher_text) {
    return cipher_text.substr(IV_SIZE, cipher_text.size() - IV_SIZE);
  }

  std::string cbcEncodeAes(const std::string& plain_text, const CryptoPP::SecByteBlock & key, byte iv[]) {
    char ct_buffer[IV_SIZE + plain_text.size() + 1];
    memcpy(ct_buffer, iv, IV_SIZE);
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(key, key.size(), iv);

    cbcEncryption.ProcessData((byte *) (ct_buffer + IV_SIZE), (byte *) plain_text.c_str(), plain_text.size());

    return std::string(ct_buffer, IV_SIZE + plain_text.size());
  }

  std::string actualDecryption(const std::string& cipher_text, const CryptoPP::SecByteBlock& key_block, const std::string& iv) {
    char pt_buffer[cipher_text.size() + 1];
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbcEncryption(key_block, key_block.size(), (byte *) iv.c_str());

    cbcEncryption.ProcessData((byte*) (pt_buffer), (byte*) (cipher_text.c_str()), cipher_text.size());

    return std::string(pt_buffer, cipher_text.size());
  }

  std::string cbcDecodeAes(const std::string& iv_cipher_text, const std::string & key) {
    const CryptoPP::SecByteBlock key_block((byte *) key.c_str(), key.size());
    const std::string iv = readIv(iv_cipher_text);
    const std::string cipher_text = removeIv(iv_cipher_text);

    return actualDecryption(cipher_text, key_block, iv);
  }

}
