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
