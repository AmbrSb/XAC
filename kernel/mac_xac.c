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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <security/mac/mac_policy.h>
#include <crypto/sha2/sha512.h>
#include <sys/priv.h>
#include <sys/imgact.h>
#include <sys/namei.h>

#include "mac_xac.h"
#include "xac_common.h"
#include "config_loader.h"

SYSCTL_DECL(_security_mac);

#define VSLOT(l) \
	((xac_vnode_label_t *)mac_label_get((l), mac_xac_slot))

#define PSLOT(l) \
	((xac_proc_label_t *)mac_label_get((l), mac_xac_slot))

#define SLOT_SET(l, v) \
	mac_label_set((l), mac_xac_slot, (intptr_t)(v))

#define XAC_LABEL_NULL ((intptr_t)NULL)

enum XacStatus {
	 XAC_STATUS_ENABLED = 0x00000001,
};

static uint32_t xac_status;
static int mac_xac_slot = 1;

uma_zone_t xac_vnode_label_zone;
uma_zone_t xac_proc_label_zone;

/**
 * Convert XAC access mode flags to accmod_t flags.
 */
uint64_t to_accessmode[XAC_ACCESS_MAX] = {
	VREAD, VWRITE, VEXEC
};

typedef struct {
	acid_t ids[XAC_TYPE_MAX];
#define l_subject_id ids[XAC_SUBJECT]
#define l_object_id ids[XAC_OBJECT]
	uint64_t ruleset_gen;
} xac_vnode_label_t;

typedef struct {
	box_rules_t box_rules;
} xac_proc_label_t;

struct label {
    int l_flags;
    intptr_t l_perpolicy[4];
};

extern struct label	*mac_vnode_label_alloc(void);

static SYSCTL_NODE(_security_mac, OID_AUTO, xac, CTLFLAG_RW, 0,
    "mac_xac policy controls");

SYSCTL_INT(_security_mac_xac, OID_AUTO, status, CTLFLAG_RD,
    &xac_status, 0, "mac_xac policy status");

/**
 * Generate access log for XAC. This is called when subject `sp` tries
 * to access object `op` and the resulting matching rule has the log
 * flag set. `v` is the verdict dictated by the matching rule. `t` is
 * the access type that was requested.
 *
 * Note: currently we are simply using the kernel logging facility.
 * eventually we will replace this with xac_log module which provides a
 * dedicated logging interface for XAC.
 */
static void
xac_log(char const *source, subject_personality_t *sp,
		object_personality_t *op, struct verdict *v, int t)
{
	char sp_str[2 * SHA512_DIGEST_LENGTH + 1];
	int i;

	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		snprintf(sp_str + 2 * i, 3, "%02x", sp->bytes[i]);

	log(LOG_INFO, "XAC Log - [%s] ruleid %u (%s) "
				  "subject: %s, object: %lu/%lu\n",
		(source + 5), v->ruleid[t], perm_str[t], sp_str,
		op->i_number, op->st_dev);
}

static void*
alloc_xac_vnode_label()
{
	void *m = uma_zalloc(xac_vnode_label_zone, 0);
	memset(m, 0, sizeof(xac_vnode_label_t));
	return (m);
}

static void
free_xac_vnode_label(void *label)
{
	uma_zfree(xac_vnode_label_zone, label);
}

static void*
alloc_xac_proc_label()
{
	void *m = uma_zalloc(xac_proc_label_zone, 0);
	memset(m, 0, sizeof(xac_proc_label_t));
	return (m);
}

static void
free_xac_proc_label(void *label)
{
	xac_proc_label_t *l;

	l = (xac_proc_label_t*)label;
	if (l == NULL)
		return;
	free_box_rules(l->box_rules);
	
	uma_zfree(xac_proc_label_zone, label);
}

static xac_proc_label_t *
proc_get_label(struct proc *p)
{
	xac_proc_label_t *l;

	if (!p->p_label)
		return (NULL);
	if (!(l = PSLOT(p->p_label))) {
		l = uma_zalloc(xac_proc_label_zone, 0);
		SLOT_SET(p->p_label, l);
	}
	return (l);
}

/**
 * Returns a pointer to the box_rules_t for process `p` which contains
 * the selfboxing ruleset for that process. The return value may dereference
 * to a NULL value which indicates that no selfboxing rules have been
 * declared for this process, and thus it is not selfboxed.
 *
 * It may return NULL if the process label is missing: possible if the
 * module is not loaded "lately".
 */
static
box_rules_t*
get_box_rules(struct proc *p)
{
	box_rules_t *br;
	xac_proc_label_t *l;

	l = proc_get_label(p);
	if (l == NULL)
		return (NULL);
	br = &l->box_rules;
	return br;
}

/**
 * Returns 1 if process `p` is in selfboxed mode, 0 otherwise.
 */
static int
is_selfboxed(struct proc *p)
{
	box_rules_t *brs;

	brs = get_box_rules(p);
	if (brs && selfbox_active(*brs))
		return (1);

	return (0);
}

static int
vnode_sha512(struct vnode *vp, struct ucred *cred, uint8_t result[64])
{
	char *tmpbuf;
	struct uio auio;
	struct iovec aiov;
	off_t offset;
	ssize_t nread;
	SHA512_CTX ctx;
	off_t file_size;
	off_t rsize;
	struct vattr va;
	int error = 0;

	tmpbuf = malloc(PAGE_SIZE, M_TEMP, M_WAITOK);
	bzero(&auio, sizeof(auio));

	SHA512_Init(&ctx);

	vn_lock(vp, LK_SHARED | LK_RETRY);
	VOP_GETATTR(vp, &va, cred);
	file_size = va.va_size;
	for (offset = 0; offset < file_size; offset += nread) {
		aiov.iov_base = tmpbuf;
		rsize = file_size - offset;
		if (rsize > PAGE_SIZE)
			rsize = PAGE_SIZE;
		aiov.iov_len = rsize;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = offset;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_resid = aiov.iov_len;
		error = VOP_READ(vp, &auio, 0, cred);
		if (error)
			goto failed;
		nread = rsize - auio.uio_resid;
		SHA512_Update(&ctx, tmpbuf, nread);
	}

	SHA512_Final(result, &ctx);

failed:
	VOP_UNLOCK(vp, 0);
	free(tmpbuf, M_TEMP);	
	return (error);
}

/**
 * Make sure that the XAC label for vnode `vp` reflects the contents
 * of the on-disk file it is associated with.
 */
static int
update_xac_label(subject_personality_t *sp, struct vnode *vp,
					struct ucred *cred)
{
	return vnode_sha512(vp, cred, sp->bytes);
}

/**
 * Checks the generation number of the data stored in label `l` against the
 * current rulesets. If the data seems to be stale, it invalidates
 * the data, causing it to be reloaded on next access.
 * This mechanism is used to ensure that subject/object labels always refer
 * to the latest version of the ruleset.
 */
static void
verify_generation(xac_vnode_label_t *l)
{
	uint64_t rg;

	rg = get_ruleset_gen();
	if (l->ruleset_gen < rg) {
		for (int i = 0; i < XAC_TYPE_MAX; i++)
			l->ids[i] = 0;
		l->ruleset_gen = rg;
	}
}

static xac_vnode_label_t *
vnode_get_label(struct vnode *vp)
{
	xac_vnode_label_t *l;

	if (!vp->v_label)
		vp->v_label = mac_vnode_label_alloc();
	if (!(l = VSLOT(vp->v_label))) {
		l = uma_zalloc(xac_vnode_label_zone, 0);
		SLOT_SET(vp->v_label, l);
	}
	return (l);
}

/**
 * Get the current subject vnode xac label. If the label is NULL then create
 * a new label and fill it with current ruleset data for the subject.
 */
static xac_vnode_label_t *
resolve_subject_label(struct vnode *vp, struct ucred *cred)
{
	xac_vnode_label_t *sl;
	subject_personality_t sp;
	struct subject *sub;
	int rc;

	sl = vnode_get_label(vp);
	verify_generation(sl);

	if (sl->l_subject_id == 0) {
		rc = update_xac_label(&sp, vp, cred);
		if (rc)
			return (NULL);
		rc = lookup_subject(&sp, &sub);
		if (rc == 0) {
			sl->l_subject_id = get_subjectid(sub);
		} else {
			sl->l_subject_id = ACID_INVAL;
		}
	}

	return (sl);
}

/**
 * Get the current object vnode xac label. If the label is NULL then create
 * a new label and fill it with current ruleset info for the object.
 */
static xac_vnode_label_t *
resolve_object_label(struct vnode *vp, struct ucred *cred)
{
	xac_vnode_label_t *ol;
	object_personality_t op;
	struct object *obj;
	struct vattr va;
	int rc;

	ol = vnode_get_label(vp);
	verify_generation(ol);

	if (ol->l_object_id == 0) {
		rc = VOP_GETATTR(vp, &va, cred);
		if (rc)
			return (NULL);
		op.i_number = (uint64_t)va.va_fileid;
		op.st_dev = (uint64_t)va.va_fsid;
		rc = lookup_object(&op, &obj);
		xac_printf(4, "lookup_object -> objid: %d rc: %d i_num: %lu  st_dev: %lu\n",
				get_objectid(obj), rc, op.i_number, op.st_dev);
		if (rc == 0) {
			ol->l_object_id = get_objectid(obj);
		} else {
			ol->l_object_id = ACID_INVAL;
		}
	}

	return (ol);
}

typedef xac_vnode_label_t *(*resolve_label)(struct vnode *vp,
										struct ucred *cred);

resolve_label label_resolvers[XAC_TYPE_MAX] = {
	resolve_subject_label,
	resolve_object_label
};

/**
 * Find the subject/object ID that the label of vnode `vp` points to
 */
static acid_t
get_id(enum ItemType type, struct vnode *vp, struct ucred *cred)
{
	xac_vnode_label_t *l;

	if (!(l = label_resolvers[type](vp, cred)))
		return (ACID_INVAL);
	KASSERT(l->ids[type] != 0, ("%d: " #type "_ID == 0", __LINE__));

	return l->ids[type];
}

/**
 * Look up the appropriate selfbox rule that applys to access `accmode` of
 * process `p` to object ID `o`, and return its verdict in `v`. If the verdict
 * denies access, `access` will be set to the first access mode for which
 * access was denied.
 */
static int
do_verdict_selfbox(struct proc *p, acid_t o, accmode_t accmode, struct verdict *v,
			int *access)
{
	int rc = 0;

	if (!ACTIVE_OID(o)) {
		return (0);
	}

	box_rules_t *brs = get_box_rules(p);
	if (brs == NULL) {
		/* Allow proccess with no MAC label to bypass selfbox */
		return (0);
	}
	if (*brs == NULL)
		return (0);

	rc = lookup_box_rule(*brs, o, v);
	if (rc == 0) {
		xac_printf(7, "selfbox verdict[%u,%u,%u][%u]: allow:%d, "
					   "flags:%d.%d.%d, log:%d%d%d\n",
					v->v_ruleid_rd, v->v_ruleid_wr, v->v_ruleid_ex, o,
					v->allow, v->v_access_rd, v->v_access_wr, v->v_access_ex,
					v->v_log_rd, v->v_log_wr, v->v_log_ex);
		for (*access = 0; *access < XAC_ACCESS_MAX; (*access)++) {
			if ((accmode & to_accessmode[*access]) &&
				(v->allow != v->access[*access])) {
				rc = EPERM;
				break;
			}
		}
	} else if (rc == ENOENT) {
		rc = 0;
	}

	return (rc);
}

/**
 * Look up the appropriate ambient rule that applys to access `accmode` of
 * process `p` to object ID `o`, and return its verdict in `v`. If the verdict
 * denies access, `access` will be set to the first access mode for which
 * access was denied.
 */
static int
do_verdict_ambient(acid_t s, acid_t o, accmode_t accmode, struct verdict *v,
			int *access)
{
	int rc = 0;

	if (!ACTIVE_SID(s) || !ACTIVE_OID(o))
		return (ENOENT);

	xac_printf(4, "lookup_rule(%u,%u)\n", s, o);
	if (lookup_rule(s, o, v) == 0) {
		xac_printf(7, "verdict[%u,%u,%u][%u,%u]: allow:%d, "
					   "flags:%d%d%d, log:%d%d%d\n",
					v->v_ruleid_rd, v->v_ruleid_wr, v->v_ruleid_ex, s, o,
					v->allow, v->v_access_rd, v->v_access_wr, v->v_access_ex,
					v->v_log_rd, v->v_log_wr, v->v_log_ex);
		for (*access = 0; *access < XAC_ACCESS_MAX; (*access)++) {
			if ((accmode & to_accessmode[*access]) &&
				(v->allow != v->access[*access])) {
				rc = EPERM;
				break;
			}
		}
		return (rc);
	}

	return (ENOENT);
}

/**
 * This macro is the main entry point to access control check function of XAC. It
 * captures the context of the caller for logging purposes.
 */
#define xac_impl(...) _xac_impl(__func__, ##__VA_ARGS__)

inline static int
_xac_impl(char const *event_source, struct vnode *svp, struct vnode *ovp,
			struct ucred *cred, accmode_t accmode)
{
	acid_t sid, oid;
	struct verdict v;
	int access = 0;
	int rc = 0;

	if (!(xac_status & XAC_STATUS_ENABLED) ||
		!rulesets_ready() ||
		!root_mounted() ||    /* implied by rulesets_ready() */
		!svp)  				  /* let kernel processes go through during bootup */
		return (0);

	config_lock();

	sid = get_id(XAC_SUBJECT, svp, cred);
	oid = get_id(XAC_OBJECT, ovp, cred);

	rc = do_verdict_selfbox(curproc, oid, accmode, &v, &access);
	if (rc == ENOENT || rc == EPERM) {
		// TODO Differentiate between failing of selfbox rules and ambient rules?
		rc = EPERM;
		sid = 0;
		goto done;
	}

	rc = do_verdict_ambient(sid, oid, accmode, &v, &access);
	if (rc == 0 || rc == EPERM)
		goto done;

	rc = do_verdict_ambient(sid, 0UL, accmode, &v, &access);
	if (rc == EPERM) {
		oid = 0;
		goto done;
	}

	rc = do_verdict_ambient(0UL, oid, accmode, &v, &access);
	if (rc == EPERM) {
		sid = 0;
		goto done;
	}

	rc = 0;

done:
	if (rc == EPERM) {
		if (v.log[access]) {
			xac_log(event_source,
						&get_subject_byid(sid)->sp,
						&get_object_byid(oid)->op,
						&v, access);
		}
	}
	config_unlock();

	return (rc);
}

static void
xac_destroy(struct mac_policy_conf *conf)
{
	uma_zdestroy(xac_vnode_label_zone);
	uma_zdestroy(xac_proc_label_zone);
}

static void
xac_init(struct mac_policy_conf *conf)
{
	xac_vnode_label_zone = uma_zcreate("xac vnode label uma zone",
								sizeof(xac_vnode_label_t),
								NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
								UMA_ZONE_ZINIT);
	xac_proc_label_zone = uma_zcreate("xac proc label uma zone",
								sizeof(xac_proc_label_t),
								NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
								UMA_ZONE_ZINIT);
	xac_status |= XAC_STATUS_ENABLED;
}

static void
dump_stats(void)
{
	// TODO
}

static void
dump_rules(void)
{
	// TODO
}

/*
 * This function acts as the gatekeeper to XAC module system calls.
 * Retruns EPERM if the caller is not authorized to make the call, and
 * returns 0 otherwise.
 */
static int
check_syscall_authorization(struct proc *p, int call)
{
	acid_t sid;
	int rc = 0;

	if (is_selfboxed(curproc))
		return (EPERM);

	switch (call)
	{
	case MAC_XAC_SYSCALL_RELOAD:
    case MAC_XAC_SYSCALL_ENABLE:
    case MAC_XAC_SYSCALL_DISABLE:
    case MAC_XAC_SYSCALL_STATS:
    case MAC_XAC_SYSCALL_DUMP:
    case MAC_XAC_SYSCALL_LOGLEVEL:
		if (!(xac_status & XAC_STATUS_ENABLED) || !rulesets_ready()) {
			rc = 0;
			break;
		}

		/*
		 * Only the xac admin executable (usually xactl) is allowed to
		 * make these system calls to the XAC kernel module.
		 */
		sid = get_id(XAC_SUBJECT, curproc->p_textvp, curproc->p_ucred);
		if (!ACTIVE_SID(sid))
			rc = EPERM;
		else
			rc = verify_admin_sp(sid);

		break;

	case MAC_XAC_SYSCALL_SELFBOX_RULE:
	case MAC_XAC_SYSCALL_SELFBOX_ENTER:
	default:
		rc = 0;
		break;
	}

	return (rc);
}

static int
xac_syscall(struct thread *td, int call, void *arg)
{
	struct selfbox_args sba;
	box_rules_t *brs;
	int rc;

	rc = check_syscall_authorization(curproc, call);
	if (rc)
		return (rc);

	switch (call)
	{
	case MAC_XAC_SYSCALL_RELOAD:
		rc = load_rulesets();
		break;

    case MAC_XAC_SYSCALL_ENABLE:
		xac_status |= XAC_STATUS_ENABLED;
		rc = 0;
		break;

    case MAC_XAC_SYSCALL_DISABLE:
		xac_status &= ~(XAC_STATUS_ENABLED);
		rc = 0;
		break;

    case MAC_XAC_SYSCALL_STATS:
		dump_stats();
		rc = 0;
		break;

    case MAC_XAC_SYSCALL_DUMP:
		dump_rules();
		rc = 0;
		break;

    case MAC_XAC_SYSCALL_LOGLEVEL:
		if ((uintptr_t)arg > LOG_LEVEL_MAX) {
			rc = EINVAL;
		} else {
			current_log_level = (uintptr_t)arg;
			rc = 0;
		}
		break;

	case MAC_XAC_SYSCALL_SELFBOX_RULE:
		rc = copyin(arg, &sba, sizeof(struct selfbox_args));
		if (rc == 0) {
			config_lock();
			brs = get_box_rules(curproc);
			if (brs)
				rc = proc_selfbox(brs, &sba);
			else
				rc = EINVAL;
			config_unlock();
		}
		break;

	case MAC_XAC_SYSCALL_SELFBOX_ENTER:
		brs = get_box_rules(curproc);
		if (brs)
			rc = proc_selfbox_enter(brs);
		else
			rc = EINVAL;
		break;

	default:
		rc = ENOSYS;
		break;
	}

	return (rc);
}

static void
xac_init_vnode_label(struct label *label)
{
	SLOT_SET(label, alloc_xac_vnode_label());
	if (VSLOT(label) == NULL) {
		xac_error("vnode label alloc failed\n");
		return;
	}
	VSLOT(label)->l_subject_id = 0;
	VSLOT(label)->l_object_id = 0;
	VSLOT(label)->ruleset_gen = 0;
}

static void
xac_destroy_vnode_label(struct label *label)
{
	if (!label)
		return;
	free_xac_vnode_label(VSLOT(label));
	SLOT_SET(label, NULL);
}

static void
xac_init_proc_label(struct label *label)
{
	SLOT_SET(label, alloc_xac_proc_label());
	if (PSLOT(label) == NULL) {
		xac_error("proc label alloc failed\n");
		return;
	}
	box_rules_t *cbr = get_box_rules(curproc);
	if (cbr == NULL || *cbr == NULL)
		PSLOT(label)->box_rules = NULL;
	else
		PSLOT(label)->box_rules = dup_box_ruleset(*cbr);
}

static void
xac_destroy_proc_label(struct label *label)
{
	if (!label)
		return;
	free_xac_proc_label(PSLOT(label));
	SLOT_SET(label, NULL);
}

static int
xac_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	return (0);
}

static int
xac_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	return (0);
}

static int
xac_proc_check_debug(struct ucred *cred, struct proc *p)
{
	if (!(xac_status & XAC_STATUS_ENABLED))
		return (0);

	if (p->p_textvp == NULL)
		return (0);

	return (EPERM);
}

static int
xac_vnode_check_access(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	return xac_impl(curproc->p_textvp, vp, cred, accmode);
}

static int
xac_vnode_check_chdir(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel)
{
	return xac_impl(curproc->p_textvp, dvp, cred, VEXEC);
}

static int
xac_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp, struct vattr *vap)
{
	return xac_impl(curproc->p_textvp, dvp, cred, VWRITE);
}

static int
xac_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_exec(struct ucred *cred,
	struct vnode *vp, struct label *vplabel,
	struct image_params *imgp, struct label *execlabel __unused)
{
	return xac_impl(curproc->p_textvp, vp, cred, VEXEC);
}

static int
xac_vnode_check_getacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type)
{
	return xac_impl(curproc->p_textvp, vp, cred, VREAD);
}

static int
xac_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return xac_impl(curproc->p_textvp, vp, cred, VREAD);
}

static int
xac_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return xac_impl(curproc->p_textvp, dvp, cred, VWRITE);
}

static int
xac_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace)
{
	return xac_impl(curproc->p_textvp, vp, cred, VREAD);
}

static int
xac_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct componentname *cnp)
{
	return xac_impl(curproc->p_textvp, dvp, cred, VREAD);
}

static int
vnode_check_page_perms(struct ucred *cred, struct vnode *vp,
		int prot)
{
	accmode_t accmode = 0;
	if (prot & VM_PROT_READ)
		accmode |= VREAD;
	if (prot & VM_PROT_WRITE)
		accmode |= VWRITE;
	if (prot & VM_PROT_EXECUTE)
		accmode |= VEXEC;
	return xac_impl(curproc->p_textvp, vp, cred, accmode);
}

static int
xac_vnode_check_mmap(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot, int flags)
{
	return vnode_check_page_perms(cred, vp, prot);
}

static int
xac_vnode_check_mprotect(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int prot)
{
	return vnode_check_page_perms(cred, vp, prot);
}

static int
xac_vnode_check_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, accmode_t accmode)
{
	return xac_impl(curproc->p_textvp, vp, cred, accmode);
}

static int
xac_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	return (0);
}

static int
xac_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	return xac_impl(curproc->p_textvp, vp, active_cred, VREAD);
}

static int
xac_vnode_check_readdir(struct ucred *cred, struct vnode *vp,
    struct label *dvplabel)
{
	return xac_impl(curproc->p_textvp, vp, cred, VREAD);
}

static int
xac_vnode_check_readlink(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return xac_impl(curproc->p_textvp, vp, cred, VREAD);
}

static int
xac_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	return (EPERM);
}

static int
xac_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	return xac_impl(curproc->p_textvp, dvp, cred, VWRITE);
}

static int
xac_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	return xac_impl(curproc->p_textvp, dvp, cred, VWRITE);
}

static int
xac_vnode_check_revoke(struct ucred *cred, struct vnode *vp,
    struct label *vplabel)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_setacl(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, acl_type_t type, struct acl *acl)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_setflags(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, u_long flags)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_setmode(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, mode_t mode)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_setowner(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, uid_t uid, gid_t gid)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct timespec atime, struct timespec mtime)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
xac_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	return xac_impl(curproc->p_textvp, vp, active_cred, VREAD);
}

static int
xac_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct label *dvplabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	int rc;

	rc = xac_impl(curproc->p_textvp, dvp, cred, VWRITE);
	if (rc != 0)
		return (rc);

	rc = xac_impl(curproc->p_textvp, vp, cred, VWRITE);
	if (rc != 0)
		return (rc);

	return (0);
}

static int
xac_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	return xac_impl(curproc->p_textvp, vp, active_cred, VWRITE);
}

static int
xac_vnode_create_extattr(struct ucred *cred, struct mount *mp,
    struct label *mntlabel, struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel, struct componentname *cnp)
{
	return xac_impl(curproc->p_textvp, vp, cred, VWRITE);
}

static int
selfbox_priv_check(struct proc *p, int priv)
{
	switch (priv) {
	/* ZFS-specific privileges */
	case PRIV_ZFS_POOL_CONFIG:
	case PRIV_ZFS_INJECT:
	case PRIV_ZFS_JAIL:
	/* UFS-specific privileges */
	case PRIV_UFS_EXTATTRCTL:
	case PRIV_UFS_QUOTAOFF:
	case PRIV_UFS_QUOTAON:
	case PRIV_UFS_SETUSE:
	/* NFS-specific privileges */
	case PRIV_NFS_DAEMON:
	case PRIV_NFS_LOCKD:
		if (is_selfboxed(p))
			return (EPERM);
	}

	return (0);
}

static int
xac_priv_check(struct ucred *cred, int priv)
{   
	int rc;

	if (!(xac_status & XAC_STATUS_ENABLED))
		return (0);

	rc = selfbox_priv_check(curproc, priv);
	if (rc)
		return (rc);

	switch (priv) {
	case PRIV_KMEM_WRITE:
		return (EPERM);
		break;

	default:
		break;
	}

	return (0);
}

// TODO
static int
xac_cred_check_visible(struct ucred *cr1, struct ucred *cr2)
{
	return (0);
}

static struct mac_policy_ops xac_ops =
{
	.mpo_destroy = xac_destroy,
	.mpo_init = xac_init,
	.mpo_syscall = xac_syscall,

	.mpo_proc_init_label = xac_init_proc_label,
	.mpo_proc_destroy_label = xac_destroy_proc_label,
	.mpo_proc_check_debug = xac_proc_check_debug,
	.mpo_cred_check_visible = xac_cred_check_visible,

	.mpo_vnode_check_access = xac_vnode_check_access,
	.mpo_vnode_check_chdir = xac_vnode_check_chdir,
	.mpo_vnode_check_create = xac_vnode_check_create,
	.mpo_vnode_check_deleteacl = xac_vnode_check_deleteacl,
	.mpo_vnode_check_deleteextattr = xac_vnode_check_deleteextattr,
	.mpo_vnode_check_exec = xac_vnode_check_exec,
	.mpo_vnode_check_getacl = xac_vnode_check_getacl,
	.mpo_vnode_check_getextattr = xac_vnode_check_getextattr,
	.mpo_vnode_check_link = xac_vnode_check_link,
	.mpo_vnode_check_listextattr = xac_vnode_check_listextattr,
	.mpo_vnode_check_lookup = xac_vnode_check_lookup,
	.mpo_vnode_check_mmap = xac_vnode_check_mmap,
	.mpo_vnode_check_mprotect = xac_vnode_check_mprotect,
	.mpo_vnode_check_open = xac_vnode_check_open,
	.mpo_vnode_check_poll = xac_vnode_check_poll,
	.mpo_vnode_check_read = xac_vnode_check_read,
	.mpo_vnode_check_readdir = xac_vnode_check_readdir,
	.mpo_vnode_check_readlink = xac_vnode_check_readlink,
	.mpo_vnode_check_relabel = xac_vnode_check_relabel,
	.mpo_vnode_check_rename_from = xac_vnode_check_rename_from,
	.mpo_vnode_check_rename_to = xac_vnode_check_rename_to,
	.mpo_vnode_check_revoke = xac_vnode_check_revoke,
	.mpo_vnode_check_setacl = xac_vnode_check_setacl,
	.mpo_vnode_check_setextattr = xac_vnode_check_setextattr,
	.mpo_vnode_check_setflags = xac_vnode_check_setflags,
	.mpo_vnode_check_setmode = xac_vnode_check_setmode,
	.mpo_vnode_check_setowner = xac_vnode_check_setowner,
	.mpo_vnode_check_setutimes = xac_vnode_check_setutimes,
	.mpo_vnode_check_stat = xac_vnode_check_stat,
	.mpo_vnode_check_unlink = xac_vnode_check_unlink,
	.mpo_vnode_check_write = xac_vnode_check_write,
	.mpo_vnode_create_extattr = xac_vnode_create_extattr,
	.mpo_vnode_destroy_label = xac_destroy_vnode_label,
	.mpo_vnode_externalize_label = xac_externalize_label,
	.mpo_vnode_init_label = xac_init_vnode_label,
	.mpo_vnode_internalize_label = xac_internalize_label,
	.mpo_priv_check = xac_priv_check,
};

#ifdef DEBUG
MAC_POLICY_SET(&xac_ops, mac_xac, "TrustedBSD MAC/XAC",
    MPC_LOADTIME_FLAG_UNLOADOK, &mac_xac_slot);
#else
MAC_POLICY_SET(&xac_ops, mac_xac, "TrustedBSD MAC/XAC",
		// XXX
    MPC_LOADTIME_FLAG_UNLOADOK, &mac_xac_slot);
#endif
