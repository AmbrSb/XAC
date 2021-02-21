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

#include <exception>
#include <map>
#include <vector>
#include <sstream>

class config_error: std::exception {
private:
	uint32_t line;
	std::string msg;
	std::string full_msg;

public:
	config_error()
		: msg{"Unkown error"}, line{0} {}
	config_error(std::string msg)
		: msg{msg}, line{0} {}
	config_error(uint32_t line, std::string msg)
		: msg{msg}, line{line} {
			update();
		}

	void
	set_line(uint32_t line)
	{
		this->line = line;
		update();
	}

	operator std::string() {
		return full_msg;
	}

	char const *what() const noexcept {
		return full_msg.c_str();
	}

	/**
	 * Update 'full_msg' field based on current state
	 * of the exception object
	 */
	void update() {
		std::ostringstream os;
		if (line)
			os << "Line " << line << ": ";
		os << msg;
		full_msg = os.str();
	}
};

void ruleset_configure(std::string path);
void ruleset_configure_nc(std::string path);
