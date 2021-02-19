#pragma once

#include <string>

#define DIGEST_LENGTH (64)

extern std::string digest_string(std::string str);
extern std::shared_ptr<unsigned char> digest_file(std::string path);
