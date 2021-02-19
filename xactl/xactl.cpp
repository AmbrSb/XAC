#include <sys/ptrace.h>

#include <exception>
#include <iostream>
#include <vector>
#include <string>

#include "xac_ops.hpp"
#include "xac_common.h"
#include "args_parser.hpp"
#include "pin.hpp"
#include "xac_parser.h"

#define HANDLE(name)                                     \
	catch (name const &e)                                \
	{                                                    \
		std::cerr << "ERROR: " << e.what() << std::endl; \
	}

#ifndef DEBUG
bool is_under_debugger()
{
	if (ptrace(PT_TRACE_ME, 0, nullptr, 0) < 0)
		return true;

	return false;
}
#endif

int main(int argc, char *argv[]) try
{
#ifndef DEBUG
	if (is_under_debugger())
		return (1);
#endif

	/**
	 * The map represents the list of valid switches and their corresponding
	 * ops and authentication requirements.
	 */
	options_short_spec_t short_switch_opts {
	/**
	 * {flag, prio, name,		args, 		auth_func, 		operation},
	 */
		{'l', 0, "set-loglevel",kHasArg,	pin_auth, 		(void*)xac_loglevel},
		{'x', 1, "change-pin",	kNoArg,		pin_auth_noset,	(void*)pin_reset},
		{'p', 2, "parse-only",	kHasArg, 	nullptr, 		(void*)ruleset_configure_nc},
		{'c', 3, "config",		kHasArg,	pin_auth,		(void*)ruleset_configure},
		{'r', 4, "reload",		kNoArg, 	pin_auth, 		(void*)xac_reload},
		{'u', 5, "dump",		kNoArg, 	nullptr, 		(void*)xac_dump_ruleset},
		{'s', 6, "stats",		kNoArg,		nullptr, 		(void*)xac_stats},
		{'e', 7, "enable",		kNoArg,		pin_auth, 		(void*)xac_enable},
		{'d', 8, "disable",		kNoArg, 	pin_auth, 		(void*)xac_disable}
	};
	auto switch_opts = create_options_spec(short_switch_opts);

	/**
	 * Array of incompatible switches a.k.a cannot be set in one invocation.
	 */
	 auto options_incompatible = create_illegal_combs(
		 {
			 {'c', 'p'},
			 {'e', 'd'}
		 });

	args_parser(argc, argv, switch_opts, options_incompatible);

    return 0;

}
HANDLE(options_error)
HANDLE(pin_error)
HANDLE(xac_ops_error)
HANDLE(config_error)