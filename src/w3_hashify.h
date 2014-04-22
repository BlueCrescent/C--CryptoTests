/*
 * w3_hashify.h
 *
 *  Created on: 22.04.2014
 *      Author: BlueCrescent
 */

#ifndef W3_HASHIFY_H_
#define W3_HASHIFY_H_

#include <string>
#include <istream>

#define BLOCK_SIZE 1024

std::string hashify(std::basic_istream<char, std::char_traits<char>> & input);


#endif /* W3_HASHIFY_H_ */
