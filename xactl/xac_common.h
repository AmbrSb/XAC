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

#pragma once

#include <sys/ptrace.h>

#define XAC_PATH_PREFIX "/etc/mac_xac"
#define XAC_CONF_PATH (XAC_PATH_PREFIX "/ruleset-usr.bin")
#define XAC_SYMTAB_PATH (XAC_PATH_PREFIX "/ruleset-usr.symtab")
#define XACTL_BIN_PATH ("/usr/local/bin/xactl")

enum mac_xac_object_type {
	MAC_XAC_OBJECT_VNODE,
	MAC_XAC_OBJECT_MOUNT,
	MAC_XAC_OBJECT_PIPE,
	MAC_XAC_OBJECT_SOCKET,
	MAC_XAC_OBJECT_SHM,
	MAC_XAC_OBJECT_SEM,
	MAC_XAC_OBJECT_PROC,
	MAC_XAC_OBJECT_THREAD,
	MAC_XAC_OBJECT_SYSTEM,
	MAC_XAC_OBJECT_DEBUG,
	MAC_XAC_OBJECT_DEVFS,
	MAC_XAC_OBJECT_BPFDESC,
	MAC_XAC_OBJECT_PRIV,
	MAC_XAC_OBJECT_KENV,
	MAC_XAC_OBJECT_KLD,
};

struct selfbox_args {
	enum mac_xac_object_type type;
	union {
		struct {
			uint64_t i_num;
			uint64_t st_dev;
			accmode_t access;
			uint8_t allow;
			uint8_t log;
		} file_rule;
	};
};

inline bool
is_under_debugger()
{
	return (ptrace(PT_TRACE_ME, 0, nullptr, 0) < 0);
}

