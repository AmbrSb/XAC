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
