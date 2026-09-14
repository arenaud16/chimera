// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Credential SID resolver: a warm credential resolves inline, a cold one parks
 * and resumes with the caller's user and group SIDs, and an identity the
 * handlers cannot name leaves its slot absent rather than failing the whole
 * set.
 */

#include <stdio.h>
#include <string.h>
#undef NDEBUG
#include <assert.h>

#include "evpl/evpl.h"
#include "vfs/vfs.h"
#include "vfs/vfs_identity.h"
#include "vfs/vfs_cred_sids.h"
#include "vfs/sdk/vfs_cred.h"
#include "vfs/sdk/vfs_sid.h"
#include "common/logging.h"
#include "prometheus-c.h"

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", name)

#define TEST_UID          4100
#define TEST_GID          4200
#define TEST_SUPP_GID     4201
#define TEST_UNKNOWN_GID  4299

#define TEST_UID_SID      "S-1-5-21-11-22-33-1100"
#define TEST_GID_SID      "S-1-5-21-11-22-33-1200"
#define TEST_SUPP_GID_SID "S-1-5-21-11-22-33-1201"

struct sids_probe {
    int                          done;
    int                          inline_fired;
    int                          have;
    struct chimera_vfs_cred_sids copy;
};

static void
sids_cb(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data)
{
    struct sids_probe *p = private_data;

    p->have = (sids != NULL);
    if (sids) {
        p->copy = *sids;
    }
    p->done = 1;
} /* sids_cb */

/* Names the test uid and two of the three gids; TEST_UNKNOWN_GID is refused. */
static int
sid_handler(
    enum chimera_vfs_identity_key       key,
    uint32_t                            id,
    const char                         *name,
    struct chimera_vfs_identity_result *out,
    void                               *private_data)
{
    (void) name;
    (void) private_data;

    if (key == CHIMERA_VFS_IDENTITY_BY_UID && id == TEST_UID) {
        out->is_group = 0;
        out->user.uid = TEST_UID;
        out->user.gid = TEST_GID;
        snprintf(out->user.username, sizeof(out->user.username), "sidtester");
        out->user.username_len = (int) strlen(out->user.username);
        snprintf(out->user.sid, sizeof(out->user.sid), TEST_UID_SID);
        return 0;
    }

    if (key == CHIMERA_VFS_IDENTITY_BY_GID && id == TEST_GID) {
        out->is_group  = 1;
        out->group.gid = TEST_GID;
        snprintf(out->group.groupname, sizeof(out->group.groupname), "sidgrp");
        out->group.groupname_len = (int) strlen(out->group.groupname);
        snprintf(out->group.sid, sizeof(out->group.sid), TEST_GID_SID);
        return 0;
    }

    if (key == CHIMERA_VFS_IDENTITY_BY_GID && id == TEST_SUPP_GID) {
        out->is_group  = 1;
        out->group.gid = TEST_SUPP_GID;
        snprintf(out->group.groupname, sizeof(out->group.groupname), "suppgrp");
        out->group.groupname_len = (int) strlen(out->group.groupname);
        snprintf(out->group.sid, sizeof(out->group.sid), TEST_SUPP_GID_SID);
        return 0;
    }

    return -1;
} /* sid_handler */

static int
sid_str_is(
    const struct chimera_sid *sid,
    const char               *expect)
{
    char buf[CHIMERA_SID_STR_MAX];

    if (chimera_sid_to_str(sid, buf, sizeof(buf)) < 0) {
        return 0;
    }
    return strcmp(buf, expect) == 0;
} /* sid_str_is */

static void
test_resolve_and_cache(
    struct chimera_vfs        *vfs,
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct chimera_vfs_cred cred;
    struct sids_probe       cold, warm;
    uint32_t                gids[2] = { TEST_SUPP_GID, TEST_UNKNOWN_GID };

    chimera_vfs_identity_register_handler(vfs, sid_handler, NULL);
    chimera_vfs_cred_init_unix(&cred, TEST_UID, TEST_GID, 2, gids);

    /* Cold: parks, resumes with the user SID and the two nameable group SIDs. */
    memset(&cold, 0, sizeof(cold));
    chimera_vfs_cred_resolve_sids(thread, &cred, sids_cb, &cold);
    while (!cold.done) {
        evpl_continue(evpl);
    }

    assert(cold.have);
    assert(sid_str_is(&cold.copy.user, TEST_UID_SID));

    /* groups[] holds the primary gid then the supplementary ones, in order.
     * The unresolvable gid keeps its slot, with no SID in it. */
    assert(cold.copy.ngroups == 3);
    assert(sid_str_is(&cold.copy.groups[0], TEST_GID_SID));
    assert(sid_str_is(&cold.copy.groups[1], TEST_SUPP_GID_SID));
    assert(!chimera_sid_present(&cold.copy.groups[2]));

    /* Warm: the same credential resolves inline, with no trip round the loop. */
    memset(&warm, 0, sizeof(warm));
    chimera_vfs_cred_resolve_sids(thread, &cred, sids_cb, &warm);
    assert(warm.done);
    assert(warm.have);
    assert(sid_str_is(&warm.copy.user, TEST_UID_SID));

    /* And the synchronous probe now finds it. */
    assert(chimera_vfs_cred_sids_lookup(thread, &cred) != NULL);

    TEST_PASS("credential resolves to its SID set and caches per thread");
} /* test_resolve_and_cache */

static void
test_lookup_misses_before_warm(struct chimera_vfs_thread *thread)
{
    struct chimera_vfs_cred cred;

    /* A credential this thread has never resolved: the synchronous probe must
     * say so rather than blocking or inventing an answer. */
    chimera_vfs_cred_init_unix(&cred, 4999, 4999, 0, NULL);
    assert(chimera_vfs_cred_sids_lookup(thread, &cred) == NULL);

    TEST_PASS("synchronous lookup misses on an unseen credential");
} /* test_lookup_misses_before_warm */

/*
 * A credential nothing can name never becomes a valid cache entry, so every
 * resolve of it takes the cold path -- but after the first one each of its
 * identities is remembered (positively or negatively) by the identity layer,
 * so every lookup of the second resolve fires its callback INLINE.  That is
 * the case the ctx->pending guard exists for: without the seeded 1 the join
 * would fire at the first inline callback, before the rest were issued, and
 * the caller would be completed against a half-built set (and the context
 * freed out from under the lookups still to come).
 */
static void
test_all_inline_completion(
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct chimera_vfs_cred cred;
    struct sids_probe       cold, again;

    chimera_vfs_cred_init_unix(&cred, 4998, 4998, 0, NULL);

    memset(&cold, 0, sizeof(cold));
    chimera_vfs_cred_resolve_sids(thread, &cred, sids_cb, &cold);
    while (!cold.done) {
        evpl_continue(evpl);
    }
    /* No handler names 4998 and NSS has no SID for anyone, so the set is
     * empty and is reported as no set at all. */
    assert(!cold.have);
    assert(chimera_vfs_cred_sids_lookup(thread, &cred) == NULL);

    /* Second resolve: every identity is now cached, so every lookup completes
     * inline and the whole resolve must finish before the call returns. */
    memset(&again, 0, sizeof(again));
    chimera_vfs_cred_resolve_sids(thread, &cred, sids_cb, &again);
    assert(again.done);
    assert(!again.have);
    assert(chimera_vfs_cred_sids_lookup(thread, &cred) == NULL);

    TEST_PASS("an all-inline resolve completes before the call returns");
} /* test_all_inline_completion */

/* Fire-and-forget warm: the result lands in the cache for a later probe. */
static void
test_warm_feeds_lookup(
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct chimera_vfs_cred cred;
    uint32_t                gids[1] = { TEST_SUPP_GID };
    int                     spins;

    chimera_vfs_cred_init_unix(&cred, TEST_UID, TEST_GID, 1, gids);
    assert(chimera_vfs_cred_sids_lookup(thread, &cred) == NULL);

    chimera_vfs_cred_sids_warm(thread, &cred);

    for (spins = 0; spins < 10000; spins++) {
        if (chimera_vfs_cred_sids_lookup(thread, &cred)) {
            break;
        }
        evpl_continue(evpl);
    }

    assert(chimera_vfs_cred_sids_lookup(thread, &cred) != NULL);
    assert(sid_str_is(&chimera_vfs_cred_sids_lookup(thread, &cred)->user,
                      TEST_UID_SID));

    TEST_PASS("warm leaves the set where a synchronous lookup finds it");
} /* test_warm_feeds_lookup */

int
main(
    int    argc,
    char **argv)
{
    struct chimera_vfs           *vfs;
    struct chimera_vfs_thread    *thread;
    struct evpl                  *evpl;
    struct chimera_vfs_module_cfg module_cfgs[2];
    struct prometheus_metrics    *metrics;

    (void) argc;
    (void) argv;

    chimera_log_init();

    metrics = prometheus_metrics_create(NULL, NULL, 0);
    assert(metrics != NULL);

    memset(module_cfgs, 0, sizeof(module_cfgs));
    snprintf(module_cfgs[0].module_name, sizeof(module_cfgs[0].module_name),
             "memfs");
    snprintf(module_cfgs[1].module_name, sizeof(module_cfgs[1].module_name),
             "memkv");

    evpl = evpl_create(NULL);
    assert(evpl != NULL);

    vfs = chimera_vfs_init(0, 0, module_cfgs, 2, "memkv", 60, 1, 1, 0, metrics);
    assert(vfs != NULL);

    thread = chimera_vfs_thread_init(evpl, vfs);
    assert(thread != NULL);

    test_lookup_misses_before_warm(thread);
    test_resolve_and_cache(vfs, thread, evpl);
    test_all_inline_completion(thread, evpl);
    test_warm_feeds_lookup(thread, evpl);

    chimera_vfs_thread_destroy(thread);
    chimera_vfs_destroy(vfs);
    evpl_destroy(evpl);
    prometheus_metrics_destroy(metrics);

    fprintf(stderr, "All credential SID resolver tests passed!\n");
    return 0;
} /* main */
