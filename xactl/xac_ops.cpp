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

#include <string>
#include <exception>

#include <sys/mac.h>

#include "mac_xac.h"
#include "xac_ops.hpp"
#include "xac_log.hpp"

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
		xac_log(0, "Request failed with error number: ", errno, ": \n");
		xac_log(0, strerror(errno));
		if (errno == ENOSYS)
			xac_log(0, "Is mac_xac module loaded?\n");
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
