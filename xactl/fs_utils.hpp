#pragma once

#include <string>

class StatFailed: std::exception {};

extern uint64_t get_filesize(std::string path);

extern void get_file_stat(std::string path, uint64_t &i_number,
				uint64_t &st_dev, uint32_t &i_gen);

