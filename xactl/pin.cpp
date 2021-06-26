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

#include "pin.hpp"

#include <iostream>
#include <fstream>
#include <sstream>

#include "fs_utils.hpp"
#include "crypto_utils.hpp"
#include "terminal.hpp"
#include "xac_log.hpp"

namespace _pin_internal {

string
pin::retrieve()
{
	string pin;

	auto filesize = get_filesize(kPinPath);
	if ((filesize) > kMaxPinStoreSize) {
		throw pin_error{"Invalid PIN store"};
	}

	std::ifstream ifs {kPinPath};
	if (!ifs.good())
		return "";
	ifs >> pin;
	if (pin.size() != filesize)
		throw pin_error{"Invalid PIN store"};

	return pin;
}

void
pin::save(string pin)
{
	std::ofstream ofs{kPinPath};
	ofs << digest_string(pin) << std::flush;
	ofs.close();
}

/**
 * Read a PIN code of size at most kMaxPinSize and at least kMinPinSize
 * from console.
 */
string
pin::read(string prompt)
{
	string pin;

	stdin_echo_off echo_ctl;
retry:
	std::cout << prompt;
	std::cin >> pin;
	std::cout << std::endl;
	if (pin.size() > kMaxPinSize) {
		xac_print("PIN must be at most ", kMaxPinSize, " characters\n");
		goto retry;
	}
	if (pin.size() < kMinPinSize) {
		xac_print("PIN must be at least ", kMinPinSize, " characters\n");
		goto retry;
	}
	return pin;
}

void
pin::reset()
{
	string new_pin, new_pin_reenter;

	new_pin = this->read("New pin:");
	new_pin_reenter = this->read("Reenter pin:");

	if (new_pin != new_pin_reenter) {
		throw pin_error{"Entered pins do not match."};
	}
	this->save(new_pin);
	xac_log(0, "PIN reset successfully.");
}

void
pin::auth_noset()
{
	string pin, challenge;
	string base;

	if (status == kAuthenticated)
		return;

	base = this->retrieve();
	if (base.size() == 0)
		return;

	pin = this->read("pin:");
	challenge = digest_string(pin);
	if (challenge != base)
		throw pin_error{"Wrong pin"};
	this->status = kAuthenticated;
}

void
pin::auth()
{
	string challenge;

	std::ifstream ifs {kPinPath};
	if (!ifs.good()) {
		this->reset();
	}
	auth_noset();
}

}
