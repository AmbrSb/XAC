#include <iostream>

#include <unistd.h>
#include <stdio.h>

#include <sys/vnode.h>
#include "../xac_lib.h"
#include "sbtest_common.h"

int main(int argc, char *argv[])
{
	int rc;

	rc = access(TARGET_FILE, W_OK);
	std::cerr << "xac selfbox denies access ";
	if (rc && errno == EPERM) {
		std::cerr << "[PASS]\n";
		rc = 0;
	} else {
		std::cerr << "[FAIL]\n";
		rc = 1;
	}
	
	std::cerr << "xac module rejects syscall ";
	rc = xacsb_allow_path(TARGET_FILE, VREAD);
	if (rc && errno == EPERM) {
		std::cerr << "[PASS]\n";
		rc = 0;
	} else {
		std::cerr << "[FAIL]\n";
		rc = 1;
	}

	return (rc);
}

