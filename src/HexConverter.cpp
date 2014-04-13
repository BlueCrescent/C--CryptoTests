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

}
