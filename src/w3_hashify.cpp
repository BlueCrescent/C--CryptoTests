/*
 * w3_hashify.cpp
 *
 *  Created on: 22.04.2014
 *      Author: BlueCrescent
 */

#include "w3_hashify.h"

#include <cryptopp/sha.h>

#define HASH_LENGTH 32

std::streamsize get_size(std::basic_istream<char, std::char_traits<char>> & input) {
  input.seekg(0, std::ios_base::end);
  return input.tellg();
}

std::string hashify(std::basic_istream<char> & input) {
  const std::streamsize size = get_size(input);
  const unsigned int last_block_size = size % BLOCK_SIZE;
  const unsigned int last_block_start = size - last_block_size;
  CryptoPP::SHA256 hasher;

  byte block_and_hash[BLOCK_SIZE + HASH_LENGTH];
  input.seekg(last_block_start);
  input.read((char *) block_and_hash, last_block_size);
  input.seekg(last_block_start);
  hasher.CalculateDigest(block_and_hash + BLOCK_SIZE, block_and_hash, last_block_size);
  while (input.tellg() != 0) {
    input.seekg(- BLOCK_SIZE, std::ios_base::cur);
    input.read((char *) block_and_hash, BLOCK_SIZE);
    input.seekg(- BLOCK_SIZE, std::ios_base::cur);
    hasher.CalculateDigest(block_and_hash + BLOCK_SIZE, block_and_hash, sizeof(block_and_hash));
  }
  return std::string((char *) (block_and_hash + BLOCK_SIZE), (unsigned int) HASH_LENGTH);
}


