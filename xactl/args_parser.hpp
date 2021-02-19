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
