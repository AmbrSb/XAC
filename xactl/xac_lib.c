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

#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mac.h>

#include "mac_xac.h"
#include "xac_common.h"

int
xacsb_enter(void)
{
	int rc;

	rc = mac_syscall("mac_xac", MAC_XAC_SYSCALL_SELFBOX_ENTER, NULL);

	return (rc);
}

int
xacsb_allow_path(char const *path, mode_t mode)
{
	struct selfbox_args arg;
	int rc;

	struct stat s;
	rc = stat(path, &s);
	if (rc)
		return (rc);

	arg.type = MAC_XAC_OBJECT_VNODE;
	arg.file_rule.i_num = s.st_ino;
	arg.file_rule.st_dev = s.st_dev;
	arg.file_rule.access = mode;
	arg.file_rule.allow = 1;
	arg.file_rule.log = 1;

	rc = mac_syscall("mac_xac", MAC_XAC_SYSCALL_SELFBOX_RULE, &arg);
	return (rc);
}

int
xacsb_allow_fd(int fd, mode_t mode)
{
	struct selfbox_args arg;
	int rc;

	struct stat s;
	rc = fstat(fd, &s);
	if (rc)
		return (rc);

	arg.type = MAC_XAC_OBJECT_VNODE;
	arg.file_rule.i_num = s.st_ino;
	arg.file_rule.st_dev = s.st_dev;
	arg.file_rule.access = mode;
	arg.file_rule.allow = 1;
	arg.file_rule.log = 1;

	rc = mac_syscall("mac_xac", MAC_XAC_SYSCALL_SELFBOX_RULE, &arg);
	return (rc);
}
