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
#include "crypto_utils.hpp"


using namespace std::literals;
using std::string;


class pin_error: public std::exception {
public:
    pin_error(std::string msg)
        : msg{msg}
    { }

    char const *what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

namespace _pin_internal {

/**
 * The pin store file location in the filesystem is
 * fixed so that we can apply a self-defense policy
 * on it
 */
string const kPinPath = "/etc/mac_xac/pin"s;
int constexpr kMaxPinSize = 32;
int constexpr kMinPinSize = 1;
/** PIN digest is stored as a hex string */
int constexpr kMaxPinStoreSize = DIGEST_LENGTH * 2;

class pin final {
public:
    pin() {}
    ~pin() {}

    pin(pin const &p) = delete;
    pin(pin &&p) = delete;
    pin& operator=(pin const &p) = delete;
    pin& operator=(pin &&p) = delete;

    void reset();
    void auth_noset();
    void auth();

private:
    enum : bool { kNotAuthenticated = false, kAuthenticated = true };
    string read(string prompt);
    string retrieve();
    void save(string pin);
    bool status = kNotAuthenticated;
};

inline pin&
get_pin()
{
    static pin pin;
    return pin;
}

}

inline void pin_auth() {
    _pin_internal::get_pin().auth();
}

inline void pin_auth_noset() {
    _pin_internal::get_pin().auth_noset();
}

inline void pin_reset() {
    _pin_internal::get_pin().reset();
}
