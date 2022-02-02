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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/sx.h>
#include <sys/counter.h>

#include "xac_common.h"
#include "config_loader.h"
#include "file_ops.h"


#define RULES_HASHTABLE_SIZE 	(128 * 1024)
#define SUBJECTS_HASHTABLE_SIZE	(512)
#define OBJECTS_HASHTABLE_SIZE	(512)
#define BOXRULES_HASHTABLE_SIZE (256)

#define MAX_RULESETS 16
#define MAX_SUBJECTS_CNT (10000  * MAX_RULESETS)
#define MAX_OBJECTS_CNT  (10000  * MAX_RULESETS)
#define MAX_RULES_CNT 	 (200000 * MAX_RULESETS)
#define NUM_RULSETS_INVALID (UINT32_MAX)

#define RULESET_PATH "/etc/mac_xac/rules.bin/"
static char *config_files[MAX_RULESETS] = {0};
static object_personality_t *config_files_personalities[MAX_RULESETS];

/**
 * 'ruleset_gen' is used to verify that MAC_XAC labels
 * refer to the latest loaded ruleset not an old one.
 * Each time a ruleset is loaded into the kernel, this
 * counter is incremented atomially by one.
 */
static uint64_t ruleset_gen = -1;

enum {
	READ = 0x01,
	WRITE = 0x02,
	EXECUTE = 0x04,
	ALLOW = 0x08,
	LOG = 0x10
};

char const *perm_str[] = {
	"READ",
	"WRITE",
	"EXECUTE"
};

#define inc_ref(x)      \
	do                    \
	{                     \
		(x->ref_cnt)++;     \
	} while (0);

#define dec_ref(x)      \
	do                    \
	{                     \
		(x->ref_cnt)--;     \
	} while (0);

struct rule_stats {
	counter_u64_t match_cnt;
	uint64_t last_match_time;
	uint64_t load_time;
};

struct rule {
	struct ruleset *rs;
	/**
	 * Rules list link in a bucket of a rules hashtable
	 */
	SLIST_ENTRY(rule) next;
	/**
	 * A unique id that identifies a rule in a ruleset file.
	 * Currently it is the rule line number
	 */
	uint32_t ruleid;
	uint32_t subid;
	uint32_t objid;
	struct rule_stats stats;
	struct verdict *v;
};

struct box_rule {
	/**
	 * Box list link in a bucket of boxes hashtable of a process
	 */
	SLIST_ENTRY(box_rule) next;
	uint32_t objid;
	struct rule_stats stats;
	struct verdict v;
};

SLIST_HEAD(box_rules_hashhead, box_rule);

struct box_ruleset {
	struct box_rules_hashhead *rules_htbl;
	u_long rules_hmask;
	struct rule_stats stats;
	int active;
};

static uma_zone_t xac_verdict_zone;
static uma_zone_t xac_rule_zone;
static uma_zone_t xac_box_rule_zone;
static uma_zone_t xac_box_ruleset_zone;

/**
 * A global list of all loaded rulesets. Each ruleset is loaded
 * from a separate file named in `config_files` array.
 */
static STAILQ_HEAD(, ruleset) rulesets;
/**
 * This is the list type used in rules hash table in each ruleset.
 */
SLIST_HEAD(rules_hashhead, rule);
/**
 * Global shared/exclusive lock used to protect `rulesets` from
 * concurrent access/monidification. It is locked exclusively only
 * rulesets are being re/loaded.
 */
struct sx rulesets_lock;
/**
 * Indicates the status of the rulesets: loaded or not.
 */
enum RulesetStatus rulesets_status = NOT_LOADED;

/**
 * Each instance of `ruleset` represents a single ruleset file
 * loaded by the kernel. It contains a hash table of rules.
 */
struct ruleset {
	STAILQ_ENTRY(ruleset) next;
	struct rules_hashhead *rules_htbl;
	u_long rules_hmask;
	/**
	 * Indicates how many time this ruleset has matched with a
	 * request in MAC framework. The match might be partial.
	 */
	struct rule_stats stats;
};

static acid_t admin_subid;

SLIST_HEAD(subjects_hashhead, subject);
SLIST_HEAD(objects_hashhead, object);
/**
 * Hash tables that map subject/object identities to the corresponding
 * subject/object structure.
 */
struct subjects_hashhead *subjects_htbl;
struct objects_hashhead *objects_htbl;
u_long objects_hmask;
u_long subjects_hmask;
/**
 * List of all loaded subjects/objects
 */
struct subject *subjects;
struct object *objects;
/**
 * Number of subjects/objects in all loaded rulesets
 */
uint32_t subjects_cnt;
uint32_t objects_cnt;
uint32_t subjects_cap;
uint32_t objects_cap;

static acid_t add_or_ref_subject(subject_personality_t *sp);
static acid_t add_or_ref_object(object_personality_t *op);

#define SUPPRESS_UNUSED_WARNING(f) (void)f

#define val_to_printf(v)       \
	_Generic((v),                \
			 subject_personality_t   \
			 	: (*((int32_t *)&v)),  \
			 object_personality_t    \
				: (*((int32_t *)&v)),  \
			 default                 \
				: v)

#define ptr_to_printf(p)       \
	_Generic((p),                \
			 subject_personality_t * \
				: (*((int32_t *)p)),   \
			 object_personality_t *  \
				: (*((int32_t *)p)),   \
			default                  \
				: *p)

/**
 * Generates a function that reads a value of type T from a blob.
 * It performs proper bounds checking to ensure blob is not accessed past
 * its end.
 */
#define DEFINE_DESERILIZER_FUNC_V(T)                                 \
	inline static int __attribute__((unused))                          \
		read_val_##T(struct blob *b, T *out, char const *msg)            \
	{                                                                  \
		SUPPRESS_UNUSED_WARNING(read_val_##T);                           \
		T v;                                                             \
		if (b->b + b->len < b->cur + sizeof(T))                          \
		{                                                                \
			xac_printf(0, "reading past end of blob!\n");                  \
			return (EINVAL);                                               \
		}                                                                \
		memcpy(&v, b->cur, sizeof(T));                                   \
		if (msg)                                                         \
			xac_printf(7, "%s: %u\n", msg, (uint32_t)val_to_printf(v));    \
		(b->cur) += sizeof(T);                                           \
		*out = v;                                                        \
		return (0);                                                      \
	}

/**
 * Generates a function that reads a pointer of type T from a blob.
 * It performs proper bounds checking to ensure blob is not accessed past
 * its end.
 */
#define DEFINE_DESERILIZER_FUNC_P(T)                                     \
	inline static int __attribute__((unused))                              \
		read_ptr_##T(struct blob *b, T **out, char const *msg)               \
	{                                                                      \
		SUPPRESS_UNUSED_WARNING(read_ptr_##T);                               \
		T *dptr;                                                             \
		if (b->b + b->len < b->cur + sizeof(T))                              \
		{                                                                    \
			xac_printf(0, "reading past end of blob!\n");                      \
			return (EINVAL);                                                   \
		}                                                                    \
		dptr = (T *)b->cur;                                                  \
		if (msg)                                                             \
			xac_printf(7, "%s: %u\n", msg, (u_int32_t)ptr_to_printf(dptr));    \
		(b->cur) += sizeof(T);                                               \
		*out = dptr;                                                         \
		return (0);                                                          \
	}

DEFINE_DESERILIZER_FUNC_P(acid_t)
DEFINE_DESERILIZER_FUNC_P(itype_t)
DEFINE_DESERILIZER_FUNC_P(flag_t)
DEFINE_DESERILIZER_FUNC_P(subject_personality_t)
DEFINE_DESERILIZER_FUNC_P(object_personality_t)

DEFINE_DESERILIZER_FUNC_V(acid_t)
DEFINE_DESERILIZER_FUNC_V(itype_t)
DEFINE_DESERILIZER_FUNC_V(flag_t)
DEFINE_DESERILIZER_FUNC_V(subject_personality_t)
DEFINE_DESERILIZER_FUNC_V(object_personality_t)

static int
subject_personality_cmp(subject_personality_t *left,
						subject_personality_t *right);
static int
object_personality_cmp(object_personality_t *left,
						object_personality_t *right);

#define RLOCK_RULESETS   (rlock_rulesets  (__func__))
#define WLOCK_RULESETS   (wlock_rulesets  (__func__))
#define RUNLOCK_RULESETS (runlock_rulesets(__func__))
#define WUNLOCK_RULESETS (wunlock_rulesets(__func__))

/**
 * Puts a shared lock on rulesets.
 * 
 * @return Returns 1 if the rulesets are loaded, zero otherwise.
 */
static int
rlock_rulesets(char const *reason)
{
	xac_printf(9, "%s [%s]\n", __func__, reason);
	sx_slock(&rulesets_lock);
	return (rulesets_status == READY);
}

static void
runlock_rulesets(char const *reason)
{
	xac_printf(9, "%s [%s]\n", __func__, reason);
	sx_sunlock(&rulesets_lock);
}

/**
 * Puts an exclusive lock on rulesets.
 * 
 * @return Returns 1 if the rulesets are loaded, zero otherwise.
 */
static int
wlock_rulesets(char const *reason)
{
	xac_printf(9, "%s [%s]\n", __func__, reason);
	sx_xlock(&rulesets_lock);
	return (rulesets_status == READY);
}

static void
wunlock_rulesets(char const *reason)
{
	xac_printf(9, "%s [%s]\n", __func__, reason);
	sx_xunlock(&rulesets_lock);
}

static void
init_verdict(struct verdict *v, uint32_t flags)
{
#define FLAG_INT(f, t) ((f & t) != 0)

	v->allow = FLAG_INT(flags, ALLOW);
	v->v_access_rd = FLAG_INT(flags, READ);
	v->v_access_wr = FLAG_INT(flags, WRITE);
	v->v_access_ex = FLAG_INT(flags, EXECUTE);

	for (int i = 0; i < XAC_ACCESS_MAX; i++) {
		v->ruleid[i] = 0;
		v->log[i] = FLAG_INT(flags, LOG);
	}
}

static uint32_t
subject_hash(subject_personality_t *sp)
{
	return (*((uint32_t*)sp->bytes));
}

static uint32_t
object_hash(object_personality_t *op)
{
	return (op->i_number);
}

static uint32_t
rule_hash(struct rule *r)
{
	uint32_t sh = subject_hash(&subjects[r->subid].sp);
	uint32_t oh = object_hash(&objects[r->objid].op);
	return (sh + oh);
}

static uint32_t
box_rule_hash(struct box_rule *br)
{
	uint32_t oh = object_hash(&objects[br->objid].op);
	return (oh);
}

uint64_t
get_ruleset_gen(void)
{
	return ruleset_gen;
}

/**
 * Event handler for mountroot event.
 */
static void
load_ruleset_event(void *not_used)
{
	load_rulesets();
}

acid_t
get_subjectid(struct subject *sub)
{
	return (sub - subjects);
}

acid_t
get_objectid(struct object *obj)
{
	return (obj - objects);
}

struct subject*
get_subject_byid(acid_t sid)
{
	return &subjects[sid];
}

struct object*
get_object_byid(acid_t oid)
{
	return &objects[oid];
}

/**
 * This pair of lock/unlock functions should wrap any sequence of
 * calls to config_loader API functions.
 */
void
config_lock(void)
{
	RLOCK_RULESETS;
}

void
config_unlock(void)
{
	RUNLOCK_RULESETS;
}

/**
 * Find subject structure that has a personality equivalent to sp.
 * 
 * @param sub If a subject with the corresponding identity is found
 * 			  `sub` is set to point to that subject structure.
 * 
 * @return Returns 0 if a match is found, ENOENT otherwise.
 */
int
lookup_subject(subject_personality_t *sp, struct subject **sub)
{
	struct subject *s, *match = NULL;
	struct subjects_hashhead *sh;
	int rc;

	if (subjects_htbl == NULL)
		return (ENOENT);

	sh = &subjects_htbl[subject_hash(sp) & subjects_hmask];
	SLIST_FOREACH(s, sh, next) {
		if (!subject_personality_cmp(sp, &s->sp)) {
			match = s;
			break;
		}
	}

	if (!match) {
		rc = (ENOENT);
	} else {
		*sub = match;
		rc = 0;
	}

	return (rc);
}

/**
 * Find object structure that has a personality equivalent to op.
 * 
 * @param obj If a object with the corresponding identity is found
 * 			  `obj` is set to point to that object structure.
 * 
 * @return Returns 0 if a match is found, ENOENT otherwise.
 */
int
lookup_object(object_personality_t *op, struct object **obj)
{
	struct object *o, *match = NULL;
	struct objects_hashhead *oh;
	int rc;

	if (objects_htbl == NULL)
		return (ENOENT);

	oh = &objects_htbl[object_hash(op) & objects_hmask];
	SLIST_FOREACH(o, oh, next) {
		if (!object_personality_cmp(op, &o->op)) {
			match = o;
			break;
		}
	}

	if (!match) {
		rc = (ENOENT);
	} else {
		*obj = match;
		rc = 0;
	}

	return (rc);
}

static int
lookup_rule_ruleset(uint32_t sid, uint32_t oid, struct ruleset *rs, struct verdict *verdict)
{
	struct rule *r, *match = NULL;

	struct subject *sub = &subjects[sid];
	uint32_t shash = subject_hash(&sub->sp);

	struct object *obj = &objects[oid];
	uint32_t ohash = object_hash(&obj->op);

	uint32_t rhash = shash + ohash;
	struct rules_hashhead *rh = &rs->rules_htbl[rhash & rs->rules_hmask];
	SLIST_FOREACH(r, rh, next) {
		if (r->subid == sid && r->objid == oid) {
			match = r;
			uint32_t ruleid = match->ruleid;
			int na = !match->v->allow;
			int rd = match->v->v_access_rd;
			int wr = match->v->v_access_wr;
			int ex = match->v->v_access_ex;
			int log_rd = match->v->v_log_rd;
			int log_wr = match->v->v_log_wr;
			int log_ex = match->v->v_log_ex;
			if (verdict->v_access_rd == (na ^ rd)) {
				if (!verdict->v_log_rd && log_rd)
					verdict->v_ruleid_rd = ruleid;
				verdict->v_log_rd |= log_rd;
			} else if (verdict->v_access_rd) {
				if (log_rd)
					verdict->v_ruleid_rd = ruleid;
				verdict->v_log_rd = log_rd;
			}
			if (verdict->v_access_wr == (na ^ wr)) {
				if (!verdict->v_log_wr && log_wr)
					verdict->v_ruleid_wr = ruleid;
				verdict->v_log_wr |= log_wr;
			} else if (verdict->v_access_wr) {
				if (log_wr)
					verdict->v_ruleid_wr = ruleid;
				verdict->v_log_wr = log_wr;
			}
			if (verdict->v_access_ex == (na ^ ex)) {
				if (!verdict->v_log_ex && log_ex)
					verdict->v_ruleid_ex = ruleid;
				verdict->v_log_ex |= log_ex;
			} else if (verdict->v_access_ex) {
				if (log_ex)
					verdict->v_ruleid_ex = ruleid;
				verdict->v_log_ex = log_ex;
			}
			verdict->v_access_rd &= (na ^ rd);
			verdict->v_access_wr &= (na ^ wr);
			verdict->v_access_ex &= (na ^ ex);
		}
	}
	if (match)
		return (0);
	else
		return (ENOENT);
}

/**
 * Find rules with subject/object sid/oid and calculate a verdict
 * based on verdicts of all matching rules.
 * 
 * @param verdict If any matching rule is found on at least of the
 * 				  loaded rulesets, verdict is set on return.
 * 
 * @return If any matching rule is found on at least of the loaded
 * 				  rulesets, returns 0, ENOENT otherwise.
 */
int
lookup_rule(uint32_t sid, uint32_t oid, struct verdict *verdict)
{
	struct ruleset *rs;
	struct verdict v;
	int matched = 0;
	int rc;

	init_verdict(&v, ALLOW | READ | WRITE | EXECUTE);

	/**
	 * Iterate over all rulesets and lookup sid/oid in each and
	 * get the verdict. The verdict from each lookup is passed
	 * to the lookup process on the next ruleset. A operation is
	 * allowed if it is allowed by all rulesets. If any rule in
	 * ruleset requires LOG on the requested operation, the
	 * corresponding log flag is set in the verdict.
	 */
	STAILQ_FOREACH(rs, &rulesets, next) {
		rc = lookup_rule_ruleset(sid, oid, rs, &v);
		if (rc == 0) {
			matched = 1;
			rs->stats.last_match_time = time_uptime;
			counter_u64_add(rs->stats.match_cnt, 1);
		}
	}

	if (matched) {
		*verdict = v;
		return (0);
	}
	return (ENOENT);
}

static void
destroy_rule(struct rule *r)
{
	if (ACTIVE_SID(r->subid) && r->subid > 0)
		dec_ref(get_subject_byid(r->subid));
	if (ACTIVE_OID(r->objid) && r->objid > 0)
		dec_ref(get_object_byid(r->objid));
	r->subid = 0;
	r->objid = 0;
	counter_u64_free(r->stats.match_cnt);
	if (r->v)
		uma_zfree(xac_verdict_zone, r->v);
	r->v = NULL;
	r->rs = NULL;
	uma_zfree(xac_rule_zone, r);
}

static void
free_box_rule(struct box_rule *br)
{
	br->objid = 0;
	counter_u64_free(br->stats.match_cnt);
	if (ACTIVE_OID(br->objid) && br->objid > 0)
		dec_ref(get_object_byid(br->objid));
	uma_zfree(xac_box_rule_zone, br);
}

static struct verdict*
create_verdict(uint32_t flags)
{
	struct verdict *v;

	v = uma_zalloc(xac_verdict_zone, 0);
	init_verdict(v, flags);

	return v;
}

static struct rule*
create_rule(struct ruleset *rs, uint32_t ruleid, uint32_t sid,
			uint32_t oid, uint32_t flags)
{
	struct rule *r;
	struct verdict *v;

	v = create_verdict(flags);
	r = uma_zalloc(xac_rule_zone, 0);
	r->ruleid = ruleid;
	r->stats.match_cnt = counter_u64_alloc(M_WAITOK);
	counter_u64_zero(r->stats.match_cnt);
	r->stats.last_match_time = 0;
	r->stats.load_time = time_uptime;
	r->subid = sid;
	r->objid = oid;
	r->v = v;
	r->rs = rs;

	return (r);
}

static struct box_rule*
create_box_rule(uint64_t i_num, uint64_t st_dev,
				accmode_t access,
				uint8_t allow, uint8_t log)
{
#define VFLAG_INT(f, t) ((f & t) != 0)
	struct box_rule *br;
	uint32_t objid;
	object_personality_t op;
	struct verdict v;

	op = (object_personality_t){i_num, st_dev, 0};

	v.allow = allow;
	v.access[XAC_READ] = VFLAG_INT(access, VREAD);
	v.access[XAC_WRITE] = VFLAG_INT(access, VWRITE);
	v.access[XAC_EXEC] = VFLAG_INT(access, VEXEC);
	v.log[XAC_READ] = log;
	v.log[XAC_WRITE] = log;
	v.log[XAC_EXEC] = log;

	objid = add_or_ref_object(&op);

	br = uma_zalloc(xac_box_rule_zone, 0);
	br->objid = objid;
	br->v = v;
	br->stats.match_cnt = counter_u64_alloc(M_WAITOK);
	counter_u64_zero(br->stats.match_cnt);

	return (br);
}

static struct box_rule*
dup_box_rule(struct box_rule *r)
{
	struct box_rule *nr;
	struct object *obj;
	int access;

	obj = get_object_byid(r->objid);

	nr = create_box_rule(obj->op.i_number, obj->op.st_dev, 0, 0, 0);
	for (access = 0; access < XAC_ACCESS_MAX; (access)++) {
		nr->v.access[access] = r->v.access[access];
		nr->v.log[access] = r->v.log[access];
	}
	nr->v.allow = r->v.allow;

	return (nr);
}

static void
add_rule(struct rule *r, struct ruleset *rs)
{
	struct rules_hashhead *rh = &rs->rules_htbl[rule_hash(r) & rs->rules_hmask];
	SLIST_INSERT_HEAD(rh, r, next);
}

static void
purge_rules(struct ruleset *rs)
{
	struct rule *r, *rt;

	for (int i = 1; i < RULES_HASHTABLE_SIZE; i++) {
		struct rules_hashhead *rh = &rs->rules_htbl[i];
		SLIST_FOREACH_SAFE(r, rh, next, rt) {
			xac_printf(7, "row: %d ", i);
			xac_printf(7, "destroying rule. subid: %d objid: %d allow: %d access: %d%d%d log: %d%d%d\n",
							r->subid, r->objid, r->v->allow, r->v->v_access_rd, r->v->v_access_wr, r->v->v_access_ex,
							r->v->v_log_rd, r->v->v_log_wr, r->v->v_log_ex);
			SLIST_REMOVE(rh, r, rule, next);
			destroy_rule(r);
		}
	}
}

static struct ruleset*
create_ruleset(void)
{
	struct ruleset *rs;
	
	rs = malloc(sizeof(struct ruleset), M_XAC, M_WAITOK | M_ZERO);
	if (!rs)
		return (NULL);
	rs->stats.match_cnt = counter_u64_alloc(M_WAITOK);
	counter_u64_zero(rs->stats.match_cnt);
	rs->stats.last_match_time = 0;
	rs->stats.load_time = time_uptime;
	rs->rules_htbl = hashinit(RULES_HASHTABLE_SIZE, M_XAC, &rs->rules_hmask);

	return (rs);
}

static struct box_ruleset*
create_box_ruleset(void)
{
	struct box_ruleset *brs;

	brs = uma_zalloc(xac_box_ruleset_zone, 0);
	if (!brs)
		return (NULL);
	brs->active = 0;
	brs->stats.match_cnt = counter_u64_alloc(M_WAITOK);
	counter_u64_zero(brs->stats.match_cnt);
	brs->stats.last_match_time = 0;
	brs->stats.load_time = time_uptime;
	brs->rules_htbl = hashinit(BOXRULES_HASHTABLE_SIZE, M_XAC, &brs->rules_hmask);

	return (brs);
}

box_rules_t
dup_box_ruleset(box_rules_t br)
{
	struct box_ruleset *brs, *nbrs;
	struct box_rule *brp;
	struct box_rules_hashhead *rh, *nrh;
	struct box_rule *nr;

	brs = (struct box_ruleset*) br;
	nbrs = create_box_ruleset();

	for (int i = 0; i < brs->rules_hmask; i++) {
		rh = &brs->rules_htbl[i];
		nrh = &nbrs->rules_htbl[i];
		SLIST_FOREACH(brp, rh, next) {
			nr = dup_box_rule(brp);
			SLIST_INSERT_HEAD(nrh, nr, next);
		}
	}
	nbrs->active = brs->active;

	return (box_rules_t)nbrs;
}

void
free_box_rules(box_rules_t br)
{
	struct box_ruleset *brs;
	struct box_rule *brp, *brpt;
	struct box_rules_hashhead *rh;

	brs = (struct box_ruleset*)br;
	if (brs == NULL)
		return;

	for (int i = 0; i < brs->rules_hmask; i++) {
		rh = &brs->rules_htbl[i];
		SLIST_FOREACH_SAFE(brp, rh, next, brpt) {
			SLIST_REMOVE(rh, brp, box_rule, next);
			free_box_rule(brp);
		}
	}
	hashdestroy(brs->rules_htbl, M_XAC, brs->rules_hmask);
}

static void
subject_personality_cpy(struct subject *sub,
						subject_personality_t *sp)
{
	memcpy(&sub->sp, sp, sizeof(subject_personality_t));
}

static void
object_personality_cpy(struct object *sub,
						object_personality_t *op)
{
	memcpy(&sub->op, op, sizeof(object_personality_t));
}

static int
subject_personality_cmp(subject_personality_t *left,
						subject_personality_t *right)
{
	for (int i = 0; i < 64; i++) {
		if (left->bytes[i] > right->bytes[i])
			return (-1);
		else if (left->bytes[i] < right->bytes[i])
			return (1);
	}
	return (0);
}

static int
object_personality_cmp(object_personality_t *left,
						object_personality_t *right)
{
	if (left->i_number > right->i_number)
		return (-1);
	if (left->i_number < right->i_number)
		return (1);
	if (left->st_dev > right->st_dev)
		return (-1);
	if (left->st_dev < right->st_dev)
		return (1);

	return (0);
}

static void
destroy_ruleset(struct ruleset *rs)
{
	hashdestroy(rs->rules_htbl, M_XAC, rs->rules_hmask);
	counter_u64_free(rs->stats.match_cnt);
	free(rs, M_XAC);
}

static int
realloc_subjects(void)
{
	int rc = 0;

	subjects_cap += INITIAL_SUBJECTS_CNT;
	subjects = realloc(subjects, subjects_cap * sizeof(struct subject), M_XAC, M_WAITOK | M_ZERO);
	if (!subjects) {
		xac_printf(0, "Memory allocation for subjects failed.\n");
		rc = ENOMEM;
	}

	return (rc);
}

static int
realloc_objects(void)
{
	int rc = 0;

	objects_cap += INITIAL_OBJECTS_CNT;
	objects = realloc(objects, objects_cap * sizeof(struct object), M_XAC, M_WAITOK | M_ZERO);

	if (!objects) {
		xac_printf(0, "Memory allocation for objects failed.\n");
		rc = ENOMEM;
	}

	return (rc);
}

static int
add_subject(subject_personality_t *sp, acid_t *sid)
{
	struct subjects_hashhead *sh;
	int rc = 0;

	if (subjects_cnt + 1 > subjects_cap) {
		rc = realloc_subjects();
		*sid = ACID_INVAL;
	}
	
	subjects_cnt++;
	*sid = subjects_cnt;
	subjects[subjects_cnt].ref_cnt = 1;
	subject_personality_cpy(&subjects[subjects_cnt], sp);

	sh = &subjects_htbl[subject_hash(sp) & subjects_hmask];
	SLIST_INSERT_HEAD(sh, &subjects[subjects_cnt], next);

	return (rc);
}

static int
add_object(object_personality_t *op, acid_t *oid)
{
	struct objects_hashhead *sh;
	int rc = 0;

	if (objects_cnt + 1 > objects_cap) {
		rc = realloc_objects();
		*oid = ACID_INVAL;
	}
	
	objects_cnt++;
	*oid = objects_cnt;
	objects[objects_cnt].ref_cnt = 1;
	object_personality_cpy(&objects[objects_cnt], op);

	sh = &objects_htbl[object_hash(op) & objects_hmask];
	SLIST_INSERT_HEAD(sh, &objects[objects_cnt], next);

	return (rc);
}

static acid_t
add_or_ref_subject(subject_personality_t *sp)
{
	struct subject *s;
	acid_t sid = ACID_INVAL;
	int rc;

	rc = lookup_subject(sp, &s);
	if (rc == 0) {
		inc_ref(s);
		sid = get_subjectid(s);
		xac_printf(7, "new subject matched with existing subject. sid: %u\n",
					sid);
	} else {
		if(add_subject(sp, &sid))
			sid = ACID_INVAL;
	}

	return (sid);
}

static acid_t
add_or_ref_object(object_personality_t *op)
{
	struct object *o;
	acid_t oid = ACID_INVAL;
	int rc;

	rc = lookup_object(op, &o);
	if (rc == 0) {
		inc_ref(o);
		oid = get_objectid(o);
		xac_printf(3, "new object matched with existing object. oid: %u\n",
					oid);
	} else {
		if(add_object(op, &oid))
			oid = ACID_INVAL;
		xac_printf(3, "new object created. oid: %u\n",
					oid);
	}

	return (oid);
}

/**
 * Deserialize a ruleset from the binary blob rsb.
 * 
 * @param rsp If deserialization is successful, and rsp is not NULL
 * 			  *rsp is set to point to the constructed ruleset.
 * 
 * @return Returns 0 if it successfully deserializes the ruleset
 * 		   in blob, and an appropriate error code otherwise.
 */
static int
deserialize_ruleset_blob(struct blob *rsb, struct ruleset **rsp)
{
#define VERIFY_SUBID(i)                                         \
	if (i > subjects_cnt || i < 0)                                \
	{                                                             \
		xac_printf(0, "Invalid subject id (%u).\n", (uint32_t)i);   \
		rc = (EINVAL);                                              \
		goto out;                                                   \
	}

#define VERIFY_OBJID(i)                                         \
	if (i > objects_cnt || i < 0)                                 \
	{                                                             \
		xac_printf(0, "Invalid object id (%u).\n", (uint32_t)i);    \
		rc = (EINVAL);                                              \
		goto out;                                                   \
	}

#define VERIFY_OP(op)                                           \
	if (op->i_number == 0)                                        \
	{                                                             \
		xac_printf(0, "Invalid inode number: %lu", op->i_number);   \
		rc = EINVAL;                                                \
		goto out;                                                   \
	}

#define VERIFY_SUB_CNT(c, m)          \
	if (c > MAX_SUBJECTS_CNT)           \
	{                                   \
		xac_printf(0, m ": %u.\n", c);    \
		rc = ENOMEM;                      \
		goto out;                         \
	}

#define VERIFY_OBJ_CNT(c, m)          \
	if (c > MAX_OBJECTS_CNT)            \
	{                                   \
		xac_printf(0, m ": %u.\n", c);    \
		rc = ENOMEM;                      \
		goto out;                         \
	}

	struct ruleset *rs = NULL;
	subject_personality_t *sp;
	object_personality_t *op;
	acid_t ruleid, subid, subcnt, objid, objcnt;
	acid_t subjects_cnt, objects_cnt, rules_cnt;
	acid_t srecs_cnt, orecs_cnt;
	acid_t *submap = NULL, *objmap = NULL;
	itype_t type;
	flag_t flags;
	int rc = 0;

#define _(expr) \
	({ rc = (expr); if (rc) goto out; })

	/**
	 * Read xactl personality from the config. This will be used to limit
	 * what process can make certain system calls to mac_xac kernel module.
	 */
	_(read_ptr_subject_personality_t(rsb, &sp, "admin_sp"));
	admin_subid = add_or_ref_subject(sp);

	/**
	 * We first read objects counts to verify their size is within
	 * acceptable range and then allocate and prepare the required
	 * objects and buffers.
	 */
	_(read_val_acid_t(rsb, &subjects_cnt, "subjects count"));
	_(read_val_acid_t(rsb, &objects_cnt, "objects count"));
	_(read_val_acid_t(rsb, &rules_cnt, "rules count"));
	if (subjects_cnt > MAX_SUBJECTS_CNT ||
			objects_cnt > MAX_OBJECTS_CNT ||
			rules_cnt > MAX_RULES_CNT) {
		xac_printf(7, "Too many entries in config.\n");
		rc = ENOMEM;
		goto out;
	}

	rs = create_ruleset();
	if (!rs) {
		xac_printf(0, "Memory allocation for ruleset failed.\n");
		rc = ENOMEM;
		goto out;
	}

	/**
	 * submap and objmap are two temporary arrays that map subject
	 * and object indices of this reulset, to indices to the global
	 * list of subject and object indices.
	 */
	submap = malloc(sizeof(acid_t) * (subjects_cnt + 1), M_XAC, M_WAITOK | M_ZERO);
	if (!submap) {
		xac_printf(0, "Memory allocation for subject map faild.\n");
		rc = ENOMEM;
		goto out;
	}

	objmap = malloc(sizeof(acid_t) * (objects_cnt + 1), M_XAC, M_WAITOK | M_ZERO);
	if (!objmap) {
		xac_printf(0, "Memory allocation for object map faild.\n");
		rc = ENOMEM;
		goto out;
	}


	/**
	 * Read subject/object personality pointers and use them to
	 * create new subjects/objects or lookup existing ones and
	 * increase their ref counts.
	 */
	for (int i = 1; i < subjects_cnt + 1; i++) {
		_(read_ptr_subject_personality_t(rsb, &sp, "subject"));
		subid = add_or_ref_subject(sp);
		submap[i] = subid;
	}
	for (int i = 1; i < objects_cnt + 1; i++) {
		_(read_ptr_object_personality_t(rsb, &op, "object"));
		/**
		 * Just a simple sanity check: inode number > 0.
		 */
		VERIFY_OP(op);
		objid = add_or_ref_object(op);
		objmap[i] = objid;
	}

	/**
	 * Read the value of subject records count and then read that
	 * many subject records.
	 */
	_(read_val_acid_t(rsb, &srecs_cnt, "subject records count"));
	VERIFY_SUB_CNT(srecs_cnt, "Too many subject records");
	for (int i = 0; i < srecs_cnt; i++) {
		/**
		 * type is just a marker for sanity checking of the ruleset binary
		 */
		_(read_val_itype_t(rsb, &type, NULL));
		if(type != XAC_SUBJECT) {
			xac_printf(0, "  Expected a subject record.\n");
			rc = EINVAL;
			goto out;
		}
		_(read_val_acid_t(rsb, &subid, "subject index"));
		VERIFY_SUBID(subid);
		_(read_val_acid_t(rsb, &objcnt, "object lines count"));
		VERIFY_OBJ_CNT(objcnt, "Too many object lines");
		for (int j = 0; j < objcnt; j++) {
			_(read_val_acid_t(rsb, &ruleid, "rule id"));
			_(read_val_flag_t(rsb, &flags, "flags"));
			_(read_val_acid_t(rsb, &objid, "line object index"));
			VERIFY_OBJID(objid);
			struct rule *r = create_rule(rs, ruleid, submap[subid],
										 objmap[objid], flags);
			add_rule(r, rs);
		}
	}

	/**
	 * Read the value of object records count and then read that
	 * many object records.
	 */
	_(read_val_acid_t(rsb, &orecs_cnt, "object records count"));
	VERIFY_OBJ_CNT(orecs_cnt, "Too many object records");
	for (int i = 0; i < orecs_cnt; i++) {
		_(read_val_itype_t(rsb, &type, NULL));
		/**
		 * type is just a marker for sanity checking of the ruleset binary
		 */
		if(type != XAC_OBJECT) {
			xac_printf(0, "  Expected an object record.\n");
			rc = EINVAL;
			goto out;
		}
		_(read_val_acid_t(rsb, &objid, "object id"));
		VERIFY_OBJID(objid);
		_(read_val_acid_t(rsb, &subcnt, "subject lines count"));
		VERIFY_SUB_CNT(subcnt, "Too many subject line");
		for (int j = 0; j < subcnt; j++) {
			_(read_val_acid_t(rsb, &ruleid, "rule id"));
			_(read_val_flag_t(rsb, &flags, "flags"));
			_(read_val_acid_t(rsb, &subid, "line subject index"));
			VERIFY_SUBID(subid);
			struct rule *r = create_rule(rs, ruleid, submap[subid],
										 objmap[objid], flags);
			add_rule(r, rs);
		}
	}
#undef _
	
	KASSERT(rc == 0,
			"ignored error condition in mac_xac load ruleset.");
	/**
	 * At this point we have successfully parsed and created a
	 * ruleset rs.
	 */
	*rsp = rs;

out:
	if (submap)
		free(submap, M_XAC);
	if (objmap)
		free(objmap, M_XAC);
	if (rc) {
		/**
		 * failure cleanup
		 */
		if (rs) {
			purge_rules(rs);
			destroy_ruleset(rs);
		}
	}
	return (rc);
}

/**
 * Parse a ruleset from the binary blob `b`. This function assumes that
 * we have an exclusive lock on the rulests.
 * 
 * @param rsp If rsp is not NULL, it is set to point the ruleset
 *		  object created in this method.
 * @return Returns 0 on success, or an appropriate error code otherwise.
 */
static int
load_ruleset(struct blob *b, struct ruleset **rsp)
{
	struct ruleset *rs;
	int rc;

	rc = deserialize_ruleset_blob(b, &rs);
	if (rc) {
		xac_printf(0, "deserialization of rulset blob failed: %d\n", rc);
		return (rc);
	}
	xac_printf(8, "rulset blob deserialized\n");

    STAILQ_INSERT_TAIL(&rulesets, rs, next);

	if (rc == 0 && rsp)
		*rsp = rs;

	return (rc);
}

/**
 * Compute and return the full path of the i-th ruleset file.
 */
static char const *
get_config_file_path(int i)
{
	char const *fname;
	static char namebuf[PATH_MAX];

	fname = config_files[i];
	snprintf(namebuf, sizeof(namebuf), "%s%s", RULESET_PATH, fname);

	return (namebuf);
}

static void
init_memory_management(void)
{
	xac_rule_zone = uma_zcreate("xac rule record zone",
								sizeof(struct rule),
								NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
								UMA_ZONE_ZINIT);
	xac_box_rule_zone = uma_zcreate("xac box rule zone",
								sizeof(struct box_rule),
								NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
								UMA_ZONE_ZINIT);
	xac_box_ruleset_zone = uma_zcreate("xac box ruleset record zone",
								sizeof(struct box_ruleset),
								NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
								UMA_ZONE_ZINIT);
	xac_verdict_zone = uma_zcreate("xac verdict record zone",
								sizeof(struct verdict),
								NULL, NULL, NULL, NULL, UMA_ALIGN_PTR,
								UMA_ZONE_ZINIT);

	uma_zone_set_max(xac_rule_zone, MAX_RULES_CNT);
	uma_zone_set_max(xac_verdict_zone, MAX_RULES_CNT);
}

static void
cleanup_memory_management(void)
{ 
	uma_zdestroy(xac_rule_zone);
	uma_zdestroy(xac_box_rule_zone);
	uma_zdestroy(xac_box_ruleset_zone);
	uma_zdestroy(xac_verdict_zone);
}

static void
destroy_rulesets(int offset)
{
	struct ruleset *rs, *trs;
	struct subjects_hashhead *sh;
	struct objects_hashhead *oh;
	struct subject *s, *ts;
	struct object *o, *to;

	xac_printf(4, "destroy_rulesets called with offset %d\n", offset);

	if (offset == 0)
		rulesets_status = NOT_LOADED;

	STAILQ_FOREACH_SAFE(rs, &rulesets, next, trs) {
		if (offset--)
			continue;
		purge_rules(rs);
		destroy_ruleset(rs);
		STAILQ_REMOVE(&rulesets, rs, ruleset, next);
	}

	if (offset == 0) {
		if (subjects_htbl) {
			for (int i = 0; i < subjects_hmask; i++) {
				sh = &subjects_htbl[i];
				SLIST_FOREACH_SAFE(s, sh, next, ts) {
					SLIST_REMOVE(sh, s, subject, next);
				}
			}
			hashdestroy(subjects_htbl, M_XAC, subjects_hmask);
			subjects_htbl = NULL;
		}
		if (subjects)
			free(subjects, M_XAC);

		if (objects_htbl) {
			for (int i = 0; i < objects_hmask; i++) {
				oh = &objects_htbl[i];
				SLIST_FOREACH_SAFE(o, oh, next, to) {
					SLIST_REMOVE(oh, o, object, next);
				}
			}
			hashdestroy(objects_htbl, M_XAC, objects_hmask);
			objects_htbl = NULL;
		}
		if (objects)
			free(objects, M_XAC);

		subjects_cnt = 0;
		objects_cnt = 0;
		subjects_cap = 0;
		objects_cap = 0;
		subjects = NULL;
		objects = NULL;
	}
}

int
selfbox_active(box_rules_t brs)
{
	struct box_ruleset *brsc;

	brsc = (struct box_ruleset*)brs;
	if (brsc)
		return (brsc->active);
	else
		return (0);

}

uint64_t
proc_selfbox(box_rules_t *br, struct selfbox_args const *sba)
{
	struct box_ruleset **brs;
	struct box_rule *r;

	brs = (struct box_ruleset**)br;
	if (*brs == NULL) {
		if ((*brs = create_box_ruleset()) == NULL) {
			xac_printf(0, "allocation of box_ruleset failed\n");
			return (-1);
		}
	}

	r = create_box_rule(sba->file_rule.i_num,
						sba->file_rule.st_dev,
						sba->file_rule.access,
						sba->file_rule.allow,
						sba->file_rule.log);

	struct box_rules_hashhead *rh =
		&(*brs)->rules_htbl[box_rule_hash(r) & (*brs)->rules_hmask];
	SLIST_INSERT_HEAD(rh, r, next);
	// XXX what if this overflows?
	ruleset_gen++;

	return (0);
}

int
proc_selfbox_enter(box_rules_t *br)
{
	struct box_ruleset **brs;

	brs = (struct box_ruleset**)br;
	if (*brs == NULL) {
		xac_printf(1, "enter attempted on non existing selfbox\n");
		return (EINVAL);
	}

	(*brs)->active = 1;
	return (0);
}

int
verify_admin_sp(acid_t sid)
{
	if (sid == admin_subid)
		return (0);

	return (EPERM);
}

int
lookup_box_rule(box_rules_t br, uint32_t oid,
					struct verdict *verdict)
{
	struct box_ruleset *brs;
	struct box_rule *brp;
	struct box_rules_hashhead *rh;

	brs = (struct box_ruleset*)br;
	if (brs == NULL || brs->active == 0)
		return (ENOENT);

	uint32_t ind = object_hash(&objects[oid].op) & brs->rules_hmask;
	rh = &brs->rules_htbl[ind];
	SLIST_FOREACH(brp, rh, next) {
		if (brp->objid == oid) {
			*verdict = brp->v;
			return (0);
		}
	}

	return (EPERM);
}

int
rulesets_ready(void)
{
	return (rulesets_status == READY);
}

int
load_rulesets(void)
{
	struct ruleset *rs, *trs;
	struct blob *rsblobs = NULL;
    int rulesets_cnt = 0;
	int i, j, rc;
	uint32_t num_rulesets_loaded = NUM_RULSETS_INVALID;

    dir_files(RULESET_PATH, config_files, &rulesets_cnt, MAX_RULESETS);
	rsblobs = malloc(rulesets_cnt * sizeof(struct blob), M_TEMP, M_WAITOK | M_ZERO);
    if (rsblobs == NULL) {
        rc = ENOMEM;
        goto fail;
    }

    /**
     * Fill in config_files list from contents of the RULESET_PATH directory
     */

	/**
	 * Read ruleset binaries.
	 */
	for (i = 0; i < rulesets_cnt; i++) {
		xac_printf(7, "going to load rulset blob (%s)\n", config_files[i]);
		rc = load_file(get_config_file_path(i), &rsblobs[i],
								&config_files_personalities[i]);
		if (rc) {
			xac_printf(0, "loading rulset blob failed error: %d (%s)\n",
						rc, config_files[i]);
			/** destroy previously loaded blobs if any */
			for (j = i - 1; j > -1; j--) {
				destroy_blob(&rsblobs[j]);
            }
			goto fail;
		}
		xac_printf(9, "rulset blob loaded\n");
	}

	WLOCK_RULESETS;

	if (rulesets_status == READY)
		xac_printf(1, "Reloading rulesets.\n");

	if (subjects_htbl == NULL)
		subjects_htbl = hashinit(SUBJECTS_HASHTABLE_SIZE, M_XAC,
								&subjects_hmask);
	if (objects_htbl == NULL)
		objects_htbl = hashinit(OBJECTS_HASHTABLE_SIZE, M_XAC,
								&objects_hmask);
	/**
	 * Find the number of currently loaded rulesets. After new
	 * rulesets are loaded successfully, we destroy the first
	 * `num_rulesets_loaded` ruleset objects from the list. Also,
	 * if something goes wrong while loading new rulesets, we will
	 * destroy any possibly loaded rulesets from position
	 * `num_rulests_loaded` till end of the list.
	 */
	num_rulesets_loaded = 0;
	STAILQ_FOREACH_SAFE(rs, &rulesets, next, trs) {
		num_rulesets_loaded++;
	}
	for (i = 0; i < rulesets_cnt; i++) {
		rc = load_ruleset(&rsblobs[i], NULL);
		destroy_blob(&rsblobs[i]);
		if (rc)
			goto fail;
		else
			xac_printf(1, "Ruleset (%s) loaded\n", config_files[i]);
	}
	/**
	 * Now that the new rulesets have been loaded and parsed
	 * we can confidently destroy the first `num_rulesets_loaded` 
	 * rulesets
	 */
    for (i = 0; i < num_rulesets_loaded; ++i) {
        rs = STAILQ_FIRST(&rulesets);

		xac_printf(4, "Removing old ruleset removed from rulesets list\n");
		STAILQ_REMOVE_HEAD(&rulesets, next);

		xac_printf(3, "Unloading old ruleset.\n");
		purge_rules(rs);

		xac_printf(4, "purged all rules in old ruleset\n");
		destroy_ruleset(rs);
		xac_printf(4, "destroyed old ruleset\n");
	}
	/**
	 * By increasing the generation number, we invalidate all previously
	 * resolved MAC_XAC labels, forcing them to refresh their data.
	 */
	ruleset_gen++;
	rulesets_status = READY;
	num_rulesets_loaded = 0;
	STAILQ_FOREACH_SAFE(rs, &rulesets, next, trs) {
		num_rulesets_loaded++;
	}
    xac_printf(0, "Now there are %d rulesets\n", num_rulesets_loaded);
	WUNLOCK_RULESETS ;
    free(rsblobs, M_TEMP);
	return (0);

fail:
	xac_printf(0, "Loading ruleset (%s) failed. Error code: %d\n",
				config_files[i], rc);
	if (num_rulesets_loaded != NUM_RULSETS_INVALID)
		destroy_rulesets(num_rulesets_loaded);
	WUNLOCK_RULESETS ;
    free(rsblobs, M_TEMP);
	return (rc);
}

static void
init_config_files_personalities(void)
{
	for (int i = 0; i < MAX_RULESETS; i++)
		config_files_personalities[i] = NULL;
}

static void
deinit_config_files_personalities(void)
{
	for (int i = 0; i < MAX_RULESETS; i++)
		if (config_files_personalities[i] != NULL)
			free(config_files_personalities[i], M_XAC);
}

void
init_config(void)
{
	ruleset_gen = 0;
	init_memory_management();
	sx_init_flags(&rulesets_lock, "xac general rulesets lock",
					SX_RECURSE);
	STAILQ_INIT(&rulesets);
	init_config_files_personalities();
	subjects_cnt = 0;
	objects_cnt = 0;
	subjects_cap = 0;
	objects_cap = 0;
	subjects = NULL;
	objects = NULL;
	subjects_htbl = NULL;
	objects_htbl = NULL;
}

void
deinit_config(void)
{
	WLOCK_RULESETS;
	destroy_rulesets(0);
	cleanup_memory_management();
	deinit_config_files_personalities();
	WUNLOCK_RULESETS;
	sx_destroy(&rulesets_lock);
}

static int
xac_cl_loader(struct module *m, int what, void *arg)
{
	int err = 0;

	switch (what)
	{
	case MOD_LOAD:
		init_config();

		if (root_mounted()) {
			load_rulesets();
		}
		break;
	case MOD_UNLOAD:
		deinit_config();
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return (err);
}

static moduledata_t xac_cl_mod = {
	"xac_config_loader",
	xac_cl_loader,
	NULL};

DECLARE_MODULE(xac_cl_loader, xac_cl_mod, SI_SUB_KLD, SI_ORDER_FIRST);
EVENTHANDLER_DEFINE(mountroot, load_ruleset_event, NULL, 0);
