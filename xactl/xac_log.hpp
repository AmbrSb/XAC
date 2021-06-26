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

#include <iostream>

extern int current_log_level;

#define HANDLE_EXCEPTION(name)        \
	catch (name const &e)               \
	{                                   \
		xac_log(0, "ERROR: ", e.what());  \
	}

enum OutMedium: uint32_t {
    None    = 0x0000,
    Console = 0x0001,
    Log     = 0x0002
};

inline time_t
get_epoch()
{
    time_t tm;
    time(&tm);
    return tm;
}

void
inline xac_log_(int) { }

template <typename H, typename... T>
inline void
xac_log_(int om /* OutMedium flags */, H const& h, T const&... args)
{
    std::cerr << h;
    xac_log_(om, args...);
}

template <typename... T>
inline void
xac_log(int level, T... args)
{
    if (level <= current_log_level)
        xac_log_(OutMedium::Log | OutMedium::Console,
                 get_epoch(), " ", args..., "\n");
}

template <typename... T>
inline void
xac_print(T... args)
{
    xac_log_(OutMedium::Console, args...);
}

