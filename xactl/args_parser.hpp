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

#include <string>
#include <vector>
#include <tuple>
#include <map>

struct option_attrs {
	int priority;
	std::string name;
	int has_arg;
	bool is_set;
	std::function<void(void)> auth_func;
	void *op;
	std::string arg;
};

using arg_priority_t = int;
using has_arg_t = enum { kNoArg = false, kHasArg = true};
using auth_func_t = std::function<void(void)>;
using func_t = void*;

using incompatible_options_t = std::vector<std::tuple<char, char>>;
using options_spec_t = std::map<char, option_attrs>;
using options_short_spec_t = std::vector<
								std::tuple<char,
										arg_priority_t,
										std::string,
										has_arg_t,
										auth_func_t,
										func_t>>;

class options_error: public std::exception {
public:
    options_error(std::string msg)
        : msg{msg}
    { }

    char const *what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

void
args_parser(int argc, char *argv[],
				options_spec_t &switch_opts,
				incompatible_options_t &options_incompatible);

incompatible_options_t
create_illegal_combs(incompatible_options_t options_incompatible);

options_spec_t
create_options_spec(options_short_spec_t options_incompatible);
