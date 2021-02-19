#include <iostream>
#include <string>
#include <exception>

#include <sys/mac.h>

#include "mac_xac.h"
#include "xac_ops.hpp"

using namespace std::literals;

namespace {

/**
 * Make a system call to MAC_XAC kernel module.
 * 
 * @param syscall_code The command code sent to the kernel module.
 * @param arg arguments to be passed to the kernel module syscall handler
 * 
 * @return Returns the return code returned by the kernel module. 0 indicates
 * 			success.
 */
int
make_syscall(enum mac_xac_syscalls syscall_code, void *arg)
{
	int rc;

	rc = mac_syscall(MAC_XAC_NAME, syscall_code, arg);
	if (rc) {
		std::cerr << "Request failed with error number: " << errno << ": "
					<< std::endl;
		perror("Error message: ");
		if (errno == ENOSYS)
			std::cerr << "Is mac_xac module loaded?" << std::endl;
	}
	
	return (rc);
}

}

/**
 * Puts the mac_xac kernel module in enforcing mode.
 * 
 * @throw Throws xac_ops_error exception if the operation fails.
 */
void xac_enable()
{
    int rc;

    rc = make_syscall(MAC_XAC_SYSCALL_ENABLE, NULL);
    if (rc) {
        throw xac_ops_error{"XAC activation failed."};
    }
}

/**
 * Disables the mac_xac kernel module.
 * 
 * @throw Throws xac_ops_error exception if the operation fails.
 */
void xac_disable()
{
    int rc;

    rc = make_syscall(MAC_XAC_SYSCALL_DISABLE, NULL);
    if (rc) {
        throw xac_ops_error{"XAC deactivation failed."};
    }
}

/**
 * Causes the mac_xac kernel module to reload is rulesets files.
 * 
 * @throw Throws xac_ops_error exception if the operation fails.
 */
void xac_reload()
{
    int rc;

    rc = make_syscall(MAC_XAC_SYSCALL_RELOAD, NULL);
    if (rc) {
        throw xac_ops_error{"XAC ruleset reload failed."};
    }
}

/**
 * Causes the mac_xac kernel module to dump its operational
 * staticstic.
 * 
 * @throw Throws xac_ops_error exception if the operation fails.
 */
void xac_stats()
{
    int rc;

    rc = make_syscall(MAC_XAC_SYSCALL_STATS, NULL);
    if (rc) {
        throw xac_ops_error{"XAC stats query failed."};
    }
}

/**
 * Changes the log level of teh mac_xac kernel module.
 * 
 * @throw Throws xac_ops_error exception if the specified log level
 *          is invalid or the operation fails.
 */
void xac_loglevel(std::string lvl)
{
    int rc;
    int log_lvl;
	char *tmp;

    log_lvl = strtoul(lvl.c_str(), &tmp, 10);
    if (*tmp != 0 || errno || tmp == lvl || log_lvl < 0) {
        throw xac_ops_error{"Invalid log level specified."s + lvl};
    }

    if (log_lvl > LOG_LEVEL_MAX) {
        throw xac_ops_error{"Invalid log level: "s + std::to_string(log_lvl)};
    }

    rc = make_syscall(MAC_XAC_SYSCALL_LOGLEVEL,
                        (void*)(uintptr_t)log_lvl);
    if (rc) {
        throw xac_ops_error{"syscall to set xac log level failed "
                                 "with error: "s + std::to_string(rc)};
    }
}

void xac_dump_ruleset()
{
    int rc;

    rc = make_syscall(MAC_XAC_SYSCALL_DUMP, NULL);
    if (rc) {
        throw xac_ops_error{"syscall to dump xac ruleset failed "
                                 "with error: "s + std::to_string(rc)};
    }
}
