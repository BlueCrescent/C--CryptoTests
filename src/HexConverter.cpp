/*
 * HexConverter.cpp
 *
 *  Created on: 12.04.2014
 *      Author: timm
 */

#include "HexConverter.h"

#include <algorithm>
#include <sstream>
#include <ios>

#include <string>

#include <cstdio>

namespace HexConverter {

  std::string toHex(const std::string & plainText) {
    std::stringstream hexCode("");
    std::for_each(plainText.begin(), plainText.end(), [&](char c){hexCode << std::hex << (int) c;});
    return hexCode.str();
  }

  std::string toChar(const std::string& hexCode) {
    if (hexCode.size() % 2 != 0)
      throw new HexStringWithoutEvenLengthException();
    std::stringstream plainText("");
    for (unsigned int i = 0; i < hexCode.size(); i += 2)
      plainText << std::hex << (char) std::stoi(hexCode.substr(i, 2), NULL, 16);
    return plainText.str();
  }

  const char* HexStringWithoutEvenLengthException::what() const noexcept {
    return "HexConverter: Hex strings need to have even length.\n";
  }

  inline char convert_bytePair_i(const unsigned int i, const std::string& hexCode) {
    char tmpBytePair[2];
    sscanf(&hexCode.c_str()[i], "%2s", tmpBytePair);
    char char_i;
    sscanf(tmpBytePair, "%x", &char_i);
    return char_i;
  }

  inline std::string executeHexToCharConversion(const std::string& hexCode) {
    std::string plainText("");
    for (unsigned int i = 0; i < hexCode.size(); i += 2) {
      plainText += convert_bytePair_i(i, hexCode);
    }
    return plainText;
  }

  std::string toChar2(const std::string& hexCode) {
    if (hexCode.size() % 2 != 0)
      throw new HexStringWithoutEvenLengthException();
    return executeHexToCharConversion(hexCode);
  }

}
