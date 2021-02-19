#include "pin.hpp"

#include <iostream>
#include <fstream>
#include <sstream>

#include "fs_utils.hpp"
#include "crypto_utils.hpp"
#include "terminal.hpp"

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
		std::cerr << "PIN must be at most " << kMaxPinSize << " characters"
					<< std::endl;
		goto retry;
	}
	if (pin.size() < kMinPinSize) {
		std::cerr << "PIN must be at least " << kMinPinSize << " characters"
					<< std::endl;
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
	std::cout << "PIN reset successfully." << std::endl;
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