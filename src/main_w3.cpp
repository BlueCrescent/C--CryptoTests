/*
 * main_w3.cpp
 *
 *  Created on: 22.04.2014
 *      Author: BlueCrescent
 */

#include "w3_hashify.h"
#include "HexConverter.h"

#include <fstream>
#include <iostream>

int main(int argc, const char * args[]) {
  if (argc < 2) {
    std::cerr << args[0] << " needs filename as argument." << std::endl;
    return 1;
  }

  const char * filename = args[1];

  std::basic_ifstream<char, std::char_traits<char>> input_file;
  input_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
  input_file.open(filename);

  const std::string final_hash = hashify(input_file);

  std::cout << "The generated hash for \"" << filename << "\" is: " << std::endl
            << HexConverter::toHex(final_hash) << std::endl << std::endl;

  return 0;
}


