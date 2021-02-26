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

#include <sys/queue.h>
#include <crypto/sha2/sha512.h>


#define XAC_CONFIG_API extern

extern char const *perm_str[];

enum Action {
	XAC_READ,
	XAC_WRITE,
	XAC_EXEC,
	XAC_ACCESS_MAX
};

enum ItemType {
	XAC_SUBJECT,
	XAC_OBJECT,
	XAC_TYPE_MAX
};

enum RulesetStatus {
	NOT_LOADED, READY
};

/**
 * Subject personality is supposed to be the unforgeable token of identity
 * we use to uniquely distinguish an excutable/process among others. Currently,
 * it is simply the SHA512 digest of the contents of the executable file.
 */
typedef struct {
	uint8_t bytes[SHA512_DIGEST_LENGTH];
	uint64_t canary;
} subject_personality_t;

/**
 * Object personality is supposed to be the unforgeable token of identity
 * we use to uniquely distinguish an files in the file system among others.
 * Currently, it is simply the combination of the inode number and device id
 * of the file. Admittedly this is not ideal, but seems to be the best general
 * option we currently have on filesystems that do not support MAC labeling,
 * notably ZFS.
 */
typedef struct { 
	uint64_t i_number;
	uint64_t st_dev;
	uint32_t canary;
} object_personality_t;

struct subject {
	/** The link in the global list of subjects */
	SLIST_ENTRY(subject) next;
	subject_personality_t sp;
	uint16_t ref_cnt;
};

struct object {
	/** The link in the global list of objects */
	SLIST_ENTRY(object) next;
	object_personality_t op;
	uint16_t ref_cnt;
};

struct verdict
{
	uint32_t ruleid[XAC_ACCESS_MAX];
#define v_ruleid_rd ruleid[XAC_READ]
#define v_ruleid_wr ruleid[XAC_WRITE]
#define v_ruleid_ex ruleid[XAC_EXEC]
	uint8_t allow;
	uint8_t access[XAC_ACCESS_MAX];
#define v_access_rd access[XAC_READ]
#define v_access_wr access[XAC_WRITE]
#define v_access_ex access[XAC_EXEC]
	uint8_t log[XAC_ACCESS_MAX];
#define v_log_rd log[XAC_READ]
#define v_log_wr log[XAC_WRITE]
#define v_log_ex log[XAC_EXEC]
};

XAC_CONFIG_API void init_config(void);
XAC_CONFIG_API void deinit_config(void);
/**
 * Puts a shared lock on the global rulesets lock
 * to prevent unloading/loading/changing of the
 * rulesets, while they are being consulted.
 */
XAC_CONFIG_API void config_lock(void);
XAC_CONFIG_API void config_unlock(void);
/**
 * Load rulesets from disk, and discard the existing
 * rulesets. Current rulesets are discarded only if
 * we can successfully load the new rulesets from disk
 * 
 * @return Returns 0 if the new rulesets are loaded
 * 			successfully, otherwise returns an appropriate
 * 			error code.
 */
XAC_CONFIG_API int load_rulesets(void);
/**
 * Find subject structure that has a personality equivalent to sp.
 * 
 * @param sub If a subject with the corresponding identity is found
 * 			  `sub` is set to point to that subject structure.
 * 
 * @return Returns 0 if a match is found, ENOENT otherwise.
 */
XAC_CONFIG_API int lookup_subject(subject_personality_t *sp, struct subject **sub);
/**
 * Find object structure that has a personality equivalent to op.
 * 
 * @param obj If a object with the corresponding identity is found
 * 			  `obj` is set to point to that object structure.
 * 
 * @return Returns 0 if a match is found, ENOENT otherwise.
 */
XAC_CONFIG_API int lookup_object(object_personality_t *op, struct object **obj);
XAC_CONFIG_API acid_t get_subjectid(struct subject *sub);
XAC_CONFIG_API acid_t get_objectid(struct object *obj);
XAC_CONFIG_API struct subject* get_subject_byid(acid_t sid);
XAC_CONFIG_API struct object* get_object_byid(acid_t oid);
XAC_CONFIG_API int lookup_rule(uint32_t sid, uint32_t oid, struct verdict *verdict);
XAC_CONFIG_API int rulesets_ready(void);
XAC_CONFIG_API uint64_t get_ruleset_gen(void);
