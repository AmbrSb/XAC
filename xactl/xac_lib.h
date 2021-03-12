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

#include <sys/stat.h>

#include "mac_xac.h"
#include "xac_common.h"
#include "xac_ops.hpp"

#define LIBXAC_API extern "C"


/**
 * Causes the configured selfbox for the current process
 * to take effect. There is no way to disable the selfbox
 * after this call. All processes forked/execed (directly
 * or indirectly) after this point will be under the effect
 * of the configured selfbox.
 */
LIBXAC_API int xacsb_enter(void);

/* File access */

/**
 * Allow 'mode' access to the device/inode that 'path'
 * currently referes to.
 */
LIBXAC_API int xacsb_allow_path(char const *path, mode_t mode);
/**
 * Allow 'mode' access to the device/inode that the open
 * file descriptor 'fd' currently referes to.
 */
LIBXAC_API int xacsb_allow_fd(int fd, mode_t mode);


/*
 * Work in progress.
 */

/* Files */
LIBXAC_API int xacsb_allow_chdir(char const *path);
LIBXAC_API int xacsb_allow_readdir(char const *path);
LIBXAC_API int xacsb_allow_chroot(char const *path);
LIBXAC_API int xacsb_allow_acl(char const *path);
LIBXAC_API int xacsb_allow_setextattr(char const *path);
LIBXAC_API int xacsb_allow_getextattr(char const *path);
LIBXAC_API int xacsb_allow_mmap(char const *path, int prot, int flags);
LIBXAC_API int xacsb_allow_mprotect(char const *path, int prot);
LIBXAC_API int xacsb_allow_readlink(char const *path);
LIBXAC_API int xacsb_allow_rename(char const *path);
LIBXAC_API int xacsb_allow_flags(char const *path, u_long flags);
LIBXAC_API int xacsb_allow_mode(char const *path, mode_t mode);
LIBXAC_API int xacsb_allow_owner(char const *path, uid_t uid, gid_t gid);
LIBXAC_API int xacsb_allow_utimes(char const *path, struct timespec atime,
		struct timespec mtime);
LIBXAC_API int xacsb_allow_unlink(char const *path);
LIBXAC_API int xacsb_allow_unlink_indir(char const *path);

/* System operations whitelisting */
LIBXAC_API int xacsb_allow_mount(void); // priv
LIBXAC_API int xacsb_allow_kld_load(void); // priv
LIBXAC_API int xacsb_allow_kld_unload(void); // priv
LIBXAC_API int xacsb_allow_devfs(void);
LIBXAC_API int xacsb_allow_kenv(void); // + priv
LIBXAC_API int xacsb_allow_reboot(int how); // priv
LIBXAC_API int xacsb_allow_settime(int how); // priv
LIBXAC_API int xacsb_allow_ioperm(int how); // priv PRIV_IO?
LIBXAC_API int xacsb_allow_sysctl(struct sysctl_oid *oidp, void *arg1,
		int arg2, struct sysctl_req *req); // see priv PRIV_SYSCTL_WRITEJAIL
LIBXAC_API int xacsb_allow_priv(int priv);

/* tty */
LIBXAC_API int xacsb_allow_tty(void); // priv

/* Jails */
LIBXAC_API int xacsb_allow_jail(); // priv

/* Swap */
LIBXAC_API int xacsb_allow_create_swapper(void);
LIBXAC_API int xacsb_allow_swapoff(void); // priv
LIBXAC_API int xacsb_allow_swapon(void);  // priv

/* Networking */
LIBXAC_API int xacsb_allow_bpf(void); // priv
LIBXAC_API int xacsb_allow_socket_create(int domain, int type, int proto);
LIBXAC_API int xacsb_allow_socket_bind(struct sockaddr *sa, int subnet_mask_len);
LIBXAC_API int xacsb_allow_socket_connect(struct sockaddr *sa, int subnet_mask_len);
LIBXAC_API int xacsb_allow_socket_listen(void);
LIBXAC_API int xacsb_allow_socket_send(void);
LIBXAC_API int xacsb_allow_socket_receive(void);

/* IPC */
LIBXAC_API int xacsb_allow_pipe(void);

LIBXAC_API int xacsb_allow_sysvmsq(void);

LIBXAC_API int xacsb_allow_sysvsem(void);

LIBXAC_API int xacsb_allow_sysvshm(void);

LIBXAC_API int xacsb_allow_posixsem_create(char const *path);
LIBXAC_API int xacsb_allow_posixsem_open(char const *ksem);

LIBXAC_API int xacsb_allow_posixshm_create(char const *path);
LIBXAC_API int xacsb_allow_posixshm_open(struct shmfd const *shmfd);

/* Processes and threads */
LIBXAC_API int xacsb_allow_debug(void); // priv
LIBXAC_API int xacsb_allow_signal_children(void);
LIBXAC_API int xacsb_allow_signal_children(void);
LIBXAC_API int xacsb_allow_signal_all(void);

/* scheduling */
LIBXAC_API int xacsb_allow_sched(void); // priv

/* users/groups */
LIBXAC_API int xacsb_allow_setauid(uid_t auid);
LIBXAC_API int xacsb_allow_setegid(gid_t egid);
LIBXAC_API int xacsb_allow_seteuid(uid_t euid);
LIBXAC_API int xacsb_allow_setgid(gid_t gid);
LIBXAC_API int xacsb_allow_setgroups(int ngroups, gid_t *gidset);
LIBXAC_API int xacsb_allow_setregid(gid_t rgid, gid_t egid);
LIBXAC_API int xacsb_allow_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
LIBXAC_API int xacsb_allow_setresuid(uid_t ruid, uid_t euid, uid_t suid);
LIBXAC_API int xacsb_allow_setreuid(uid_t ruid, uid_t euid);
LIBXAC_API int xacsb_allow_setuid(uid_t uid);

/* Cred visibility */
LIBXAC_API int xacsb_allow_see_other_uids();
LIBXAC_API int xacsb_allow_see_other_gids();

