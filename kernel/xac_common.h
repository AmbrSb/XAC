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
