#include <iostream>

#include <stdio.h>
#include <unistd.h>
#include <sys/mac.h>
#include <sys/vnode.h>

#include "../xac_lib.h"
#include "sbtest_common.h"



/*
 * Test Structure
 * 1- Create file 'TARGET_FILE' and make system call to XAC module
 *    to whitelist it for READ access.
 * 2- Activate the sandbox
 * 3- Run the target executable which verifies sandbox functionality
 */


int main(int argc, char *argv[])
{
	int rc = 0;
	struct selfbox_args arg;

	rc = touch_file(TARGET_FILE);
	if (rc) {
		perror("touch target file");
		exit(1);
	}

	rc = xacsb_allow_path(TARGET_FILE, VREAD);
	if (rc) {
		perror("selfbox_allow_path");
		exit(2);
	}

	rc = xacsb_enter();
	if (rc) {
		perror("selfbox_enter");
		exit(3);
	}

	if (fork() == 0) {
		char *args[] = {(char*)"sbtest_c", NULL};
		execve("./xactl_sbtest_c_01", args, NULL);
	}
	
	return (0);
}

