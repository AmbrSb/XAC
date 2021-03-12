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

#include <sys/malloc.h>

MALLOC_DECLARE(M_XAC);

typedef uint32_t acid_t;
typedef uint32_t itype_t;
typedef uint32_t flag_t;

#define ACID_MAX UINT32_MAX
#define ACID_INVAL ACID_MAX

#define INITIAL_SUBJECTS_CNT 128;
#define INITIAL_OBJECTS_CNT 128;

#define ACTIVE_SID(s) (s != ACID_INVAL)
#define ACTIVE_OID(o) (o != ACID_INVAL)

#define xac_printf(level, fmt, ...)                              \
    do                                                            \
    {                                                             \
        if (level <= current_log_level)                           \
        {                                                         \
            unsigned p_time_now = time_second;                    \
            if (curproc->p_textvp)                                \
                uprintf("%u ms " fmt, p_time_now, ##__VA_ARGS__); \
            else                                                  \
                printf("%u ms " fmt, p_time_now, ##__VA_ARGS__);  \
        }                                                         \
    } while (0)

#define xac_error(msg, ...) \
	xac_printf(0, msg, ##__VA_ARGS__)

extern int current_log_level;

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
