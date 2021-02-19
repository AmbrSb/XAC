#include <sys/stat.h>

#include "fs_utils.hpp"

uint64_t
get_filesize(std::string path)
{
	struct stat st;
	uint64_t size;
	int rc;

	rc = stat(path.c_str(), &st);
	if (rc)
		return 0;
	size = st.st_size;

	return size;
}

void
get_file_stat(std::string path, uint64_t &i_number,
				uint64_t &st_dev, uint32_t &i_gen)
{
	int error;

	struct stat st;
	error = stat(path.c_str(), &st);
	if (error) {
		perror("stat");
		throw StatFailed{};
	}
	i_number = (uint64_t)st.st_ino;
	st_dev = (uint64_t)st.st_dev;
	i_gen = st.st_gen;
}
