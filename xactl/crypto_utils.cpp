/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2021, Amin Saba
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <new>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "crypto_utils.hpp"

class InvalidPathError: std::exception {};
class FileReadError: std::exception {};

using namespace std::literals;

namespace {

int constexpr kDigestionRounds = 544202;

template <int N>
static std::string
get_hex_representation(uint8_t const (&bytes)[N])
{
	std::ostringstream os;
	os.fill('0');
	os << std::hex;
	for (int i = 0; i < N; i++)
		os << std::setw(2) << (unsigned int)bytes[i];
	return os.str();
}

}

/**
 * Calculates SHA of size s on input buffer b of length l
 * and puts the result in buffer o
 */
#define CALC_SHA(s, b, l, o)                               \
	do                                                     \
	{                                                      \
		static_assert(sizeof(o) >= SHA##s##_DIGEST_LENGTH, \
					  "digest buffer too small!");         \
		SHA##s##_CTX ctx;                                  \
		SHA##s##_Init(&ctx);                               \
		SHA##s##_Update(&ctx, b, l);		               \
		SHA##s##_Final(o, &ctx);                           \
	} while (0)

/**
 * Calculates a customized recursive SHA512 hash of a string
 * 
 * @param str Input string
 * 
 * @return Returns a hex string representing the calculated digest.
 */
std::string
digest_string(std::string str)
{
	uint8_t *buffer;
	uint8_t digest[SHA512_DIGEST_LENGTH];
	std::string hex_str;
	
	buffer = static_cast<uint8_t*>(malloc(str.size()));
	if (buffer == nullptr) {
		throw std::bad_alloc{};
	}
	memset(buffer, 0, str.size());
	strncpy((char*)buffer, str.c_str(), str.size());
	CALC_SHA(512, buffer, str.size(), digest);
	/**
	 * Slow down possible brute force attack by requiring multiple
	 * rounds of hashing.
	 */
	for (int i = 0; i < kDigestionRounds; i++)
		CALC_SHA(512, digest, sizeof(digest), digest);

	free(buffer);
	hex_str = get_hex_representation(digest);
	return hex_str;
}

/**
 * Calculates SHA512 hash of contents of a file.
 * 
 * @param path The absolute path of the file whose sha512 disgest is
 * 				to be calculated.
 * 
 * @return Returns a shared_ptr to the binary buffer holding the result.
 */
std::shared_ptr<unsigned char>
digest_file(std::string path)
{
	constexpr uint32_t req = 1024;
	unsigned char buf[req];
	int len;
	int fd;
	SHA512_CTX ctx;
	std::shared_ptr<unsigned char> digest;

	digest = std::shared_ptr<unsigned char> (
			(unsigned char*)malloc(SHA512_DIGEST_LENGTH), free);
	fd = open(path.c_str(), O_RDONLY);
	if (fd < 0) {
		perror("open");
		throw InvalidPathError{};
	}
	SHA512_Init(&ctx);
	while ((len = read(fd, buf, req)) > 0)
		SHA512_Update(&ctx, buf, len);
	if (len < 0) {
		perror("read");
		throw FileReadError{};
	}
	SHA512_Final(digest.get(), &ctx);
	close(fd);

    return digest;
}
