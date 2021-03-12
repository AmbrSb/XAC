#include <iostream>

#include <unistd.h>
#include <stdio.h>

#include "sbtest_common.h"

int main(int argc, char *argv[])
{
	int rc;

	rc = access(TARGET_FILE, W_OK);
	if (rc && errno == EPERM) {
		std::cerr << "[PASS]\n";
		rc = 0;
	} else {
		std::cerr << "[FAIL]\n";
		rc = 1;
	}
	
	return (rc);
}

