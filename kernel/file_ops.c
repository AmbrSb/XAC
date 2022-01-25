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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/event.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/lockf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/rwlock.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/uio.h>
#include <sys/malloc.h>

#include "xac_common.h"
#include "config_loader.h"
#include "file_ops.h"

#define DIRENT_MINSIZE (sizeof(struct dirent) - (MAXNAMLEN+1) + 4)

static const int VN_OPEN_DONE = 0x01;
static const int VOP_GETATTR_DONE = 0x02;

static void
init_blob(struct blob *b)
{
	b->b = b->cur = NULL;
	b->len = 0;
}

void
destroy_blob(struct blob *b)
{
	b->len = 0;
	if (b->b)
		free(b->b, M_XAC);
	b->b = NULL;
}

static int
get_vp_locked(char const* path,
              struct vnode** vp,
              struct vattr *va,
              struct thread *td,
              int *status)
{
	struct nameidata nid;
    int error;
    int flags = FREAD;

    *status = 0;

	KASSERT(td->td_ucred != NULL, ("td is null"));

	pwd_ensure_dirs();
	NDINIT(&nid, LOOKUP, 0, UIO_SYSSPACE, path, td);
	error = vn_open(&nid, &flags, 0, NULL);
	NDFREE(&nid, NDF_ONLY_PNBUF);
    if (error) {
        xac_printf(0, "error: %d\n", error);
        return (error);
    }
    *status |= VN_OPEN_DONE;

    *vp = nid.ni_vp;

	KASSERT(VOP_ISLOCKED(*vp), ("vp %p is not locked", *vp));

	error = VOP_GETATTR(*vp, va, td->td_ucred);
	if (error) {
		return (error);
    }
    *status |= VOP_GETATTR_DONE;

    return (0);
}

static void
put_vp_locked(struct vnode* vp, struct thread *td, int status)
{
#if __FreeBSD__ < 13
	VOP_UNLOCK(vp, 0);
#else
	VOP_UNLOCK(vp);
#endif

    if (status & VN_OPEN_DONE) {
        (void)vn_close(vp, FREAD, td->td_ucred, td);
    }
}

/**
 * Read the file pointed to by path and load its raw contents
 * into the blob pointed to by rb.
 */
int
load_file(char const *path, struct blob *rb,
					object_personality_t **rs_personality)
{
	struct uio auio;
	struct iovec aiov;
    struct vnode *vp;
	struct vattr va;
	off_t offset;
	ssize_t nread;
	off_t file_size;
	off_t rsize;
    int status;
	int error;
	init_blob(rb);

    error = get_vp_locked(path, &vp, &va, curthread, &status);
	if (error) {
		xac_printf(0, "vp_get_locked() failed\n");
		goto failed;
	}

	if (*rs_personality == NULL) {
		*rs_personality = malloc(sizeof(object_personality_t), M_XAC, M_WAITOK | M_ZERO);
		(*rs_personality)->i_number = (uint64_t)va.va_fileid;
		(*rs_personality)->st_dev = va.va_fsid;
		(*rs_personality)->canary = 0;
	} else {
		if ((*rs_personality)->i_number != (uint64_t)va.va_fileid ||
				(*rs_personality)->st_dev != va.va_fsid) {
			xac_printf(0, "Ruleset file (%s) personality has changed. "
						   "Refusing to load ruleset.\n", path);
			error = (EINVAL);
			goto failed;
		}
	}

	file_size = va.va_size;
	if (file_size > 1024 * 1024 * 1024) {
		xac_printf(0, "Config file too large: %lu", file_size);
		error = (ENOMEM);
		goto failed;
	}

	rb->b = rb->cur = malloc(file_size, M_XAC, M_ZERO | M_WAITOK);
	if (!rb->b) {
		xac_printf(0, "Allocation of blob failed. file size: %lu", file_size);
		error = (ENOMEM);
		goto failed;
	}
	bzero(&auio, sizeof(auio));
	for (offset = 0; offset < file_size; offset += nread) {
		aiov.iov_base = rb->b + offset;
		rsize = file_size - offset;
		aiov.iov_len = rsize;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = offset;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_resid = aiov.iov_len;
		error = VOP_READ(vp, &auio, 0, curthread->td_ucred);
		if (error) {
			xac_printf(0, "VOP_READ failed\n");
			goto failed;
		}
		nread = rsize - auio.uio_resid;
	}
	rb->len = file_size;

failed:
    put_vp_locked(vp, curthread, status);

	if (error && rb->b)
		destroy_blob(rb);
	return (error);
}

static int
get_next_dirent(struct vnode *vp, struct dirent **dpp, char *dirbuf,
		int dirbuflen, off_t *off, char **cpos, int *len,
		int *eofflag, struct thread *td)
{
	int error, reclen;
	struct uio uio;
	struct iovec iov;
	struct dirent *dp;

	KASSERT(VOP_ISLOCKED(vp), ("vp %p is not locked", vp));
	KASSERT(vp->v_type == VDIR, ("vp %p is not a directory", vp));

	if (*len == 0) {
		iov.iov_base = dirbuf;
		iov.iov_len = dirbuflen;

		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = *off;
		uio.uio_resid = dirbuflen;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = td;

		*eofflag = 0;

        error = VOP_READDIR(vp, &uio, td->td_ucred, eofflag,
		    		NULL, NULL);
		if (error)
			return (error);

		*off = uio.uio_offset;

		*cpos = dirbuf;
		*len = (dirbuflen - uio.uio_resid);

		if (*len == 0)
			return (ENOENT);
	}

	dp = (struct dirent *)(*cpos);
	reclen = dp->d_reclen;
	*dpp = dp;

	/* check for malformed directory.. */
	if (reclen < DIRENT_MINSIZE)
		return (EINVAL);

	*cpos += reclen;
	*len -= reclen;

	return (0);
}

/**
 * Get a list of regular files in the directory 'path'.
 *
 * @param filenames  On success contains an array of size 'filescnt'
 *        where each elements contains a null-terminated string
 *        corresponding to one of the files in 'path'.
 * @param filescnt  The number of regular files in 'paht'. 
 * @param max_cnt:  Only the first max_cnt entries will be returned.
 */
int
dir_files(char const * path, char *filenames[],
          int *filescnt, int max_cnt)
{
	char *dirbuf, *cpos;
	int eofflag, dirbuflen, len;
	off_t off;
	struct dirent *dp;
	struct vattr va;
    struct vnode *vp;
    int status;
    int i, error;


    for (i = 0; i < max_cnt; ++i)
        if (filenames[i] != NULL) {
            free(filenames[i], M_XAC);
            filenames[i] = NULL;
        }

    error = get_vp_locked(path, &vp, &va, curthread, &status);
    if (error)
        return (error);
	KASSERT(vp->v_type == VDIR, ("vp %p is not a directory", vp));
    
	dirbuflen = DEV_BSIZE;
	if (dirbuflen < va.va_blocksize)
		dirbuflen = va.va_blocksize;
	dirbuf = (char*)malloc(dirbuflen, M_TEMP, M_WAITOK);

	off = 0;
	len = 0;

	do {
		error = get_next_dirent(vp, &dp, dirbuf, dirbuflen, &off,
					&cpos, &len, &eofflag, curthread);
		if (error)
			goto out;

		if (dp->d_type == DT_REG && dp->d_fileno != 0) {
            if (*filescnt == max_cnt) {
                xac_printf(0, "Too many files in rules.d directory\n");
                break;
            }
			xac_printf(0, "%s\n", dp->d_name);
            filenames[*filescnt] = malloc(dp->d_namlen + 1, M_XAC, M_ZERO | M_WAITOK);
            if (filenames[*filescnt] == NULL) {
                xac_printf(0, "Cannot allocate memory for config file paths!\n");
                break;
            }
            strncpy(filenames[*filescnt], dp->d_name, dp->d_namlen);
            filenames[*filescnt][dp->d_namlen] = 0;
            *filescnt = *filescnt + 1;
		}
	} while (len > 0 || !eofflag);

out:
	free(dirbuf, M_TEMP);
    put_vp_locked(vp, curthread, status);
	return (0);
}

