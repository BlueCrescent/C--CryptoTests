/*
 * HexConverter.h
 *
 *  Created on: 12.04.2014
 *      Author: timm
 */

#ifndef HEXCONVERTER_H_
#define HEXCONVERTER_H_

#include <string>
#include <exception>

namespace HexConverter {

  class HexStringWithoutEvenLengthException : public std::exception {
    virtual const char * what() const noexcept;
  };

  std::string toHex(const std::string & plainText);

  std::string toChar(const std::string & hexCode);
};

#endif /* HEXCONVERTER_H_ */
