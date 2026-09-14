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

/*
 * Eviction.  The cache is a fixed number of buckets with a bounded chain each,
 * so resolving many more credentials than it holds forces entries to be
 * recycled.  Whatever it chooses to keep must still be right: a cached set
 * belongs to the credential that asked for it, or the credential is not cached
 * at all.  Anything else means an entry was repurposed while something still
 * held it, or a stale entry was matched on its hash alone.
 *
 * Deliberately probabilistic rather than a hand-built bucket collision: the
 * bucket count and chain depth are private to vfs_cred_sids.c, and a test that
 * hardcoded them would silently stop forcing eviction the day they changed.
 */
#define TEST_EVICT_N        400
#define TEST_EVICT_UID_BASE 700000
#define TEST_EVICT_GID_BASE 800000

/* Indices [0, TEST_EVICT_N) belong to the eviction sweep; the pin sweep below
 * takes the next TEST_PIN_N.  evict_handler names the whole range. */
#define TEST_PIN_FIRST      TEST_EVICT_N
#define TEST_PIN_N          300
#define TEST_EVICT_RANGE    (TEST_EVICT_N + TEST_PIN_N)

/* Credentials nothing names, used only to push entries out of a full bucket. */
#define TEST_NEST_UID_BASE  900000
#define TEST_NEST_GID_BASE  910000

static void
evict_expect_user_sid(
    int   i,
    char *buf,
    int   buflen)
{
    snprintf(buf, buflen, "S-1-5-21-500-600-700-%d", 1000 + i);
} /* evict_expect_user_sid */

static void
evict_expect_group_sid(
    int   i,
    char *buf,
    int   buflen)
{
    snprintf(buf, buflen, "S-1-5-21-500-600-700-%d", 2000 + i);
} /* evict_expect_group_sid */

/* Gives every credential in the sweep its own distinct user and group SID. */
static int
evict_handler(
    enum chimera_vfs_identity_key       key,
    uint32_t                            id,
    const char                         *name,
    struct chimera_vfs_identity_result *out,
    void                               *private_data)
{
    (void) name;
    (void) private_data;

    if (key == CHIMERA_VFS_IDENTITY_BY_UID &&
        id >= TEST_EVICT_UID_BASE && id < TEST_EVICT_UID_BASE + TEST_EVICT_RANGE) {
        out->is_group = 0;
        out->user.uid = id;
        out->user.gid = TEST_EVICT_GID_BASE + (id - TEST_EVICT_UID_BASE);
        snprintf(out->user.username, sizeof(out->user.username), "ev%u", id);
        out->user.username_len = (int) strlen(out->user.username);
        evict_expect_user_sid((int) (id - TEST_EVICT_UID_BASE),
                              out->user.sid, sizeof(out->user.sid));
        return 0;
    }

    if (key == CHIMERA_VFS_IDENTITY_BY_GID &&
        id >= TEST_EVICT_GID_BASE && id < TEST_EVICT_GID_BASE + TEST_EVICT_RANGE) {
        out->is_group  = 1;
        out->group.gid = id;
        snprintf(out->group.groupname, sizeof(out->group.groupname),
                 "evg%u", id);
        out->group.groupname_len = (int) strlen(out->group.groupname);
        evict_expect_group_sid((int) (id - TEST_EVICT_GID_BASE),
                               out->group.sid, sizeof(out->group.sid));
        return 0;
    }

    return -1;
} /* evict_handler */

static void
test_eviction_keeps_entries_honest(
    struct chimera_vfs        *vfs,
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct chimera_vfs_cred cred;
    struct sids_probe       p;
    char                    expect[CHIMERA_SID_STR_MAX];
    int                     i, cached = 0;

    chimera_vfs_identity_register_handler(vfs, evict_handler, NULL);

    for (i = 0; i < TEST_EVICT_N; i++) {
        chimera_vfs_cred_init_unix(&cred, TEST_EVICT_UID_BASE + i,
                                   TEST_EVICT_GID_BASE + i, 0, NULL);

        memset(&p, 0, sizeof(p));
        chimera_vfs_cred_resolve_sids(thread, &cred, sids_cb, &p);
        while (!p.done) {
            evpl_continue(evpl);
        }

        /* Each resolve must answer with its OWN credential's SIDs, however
         * much churn the cache is under by now. */
        assert(p.have);
        evict_expect_user_sid(i, expect, sizeof(expect));
        assert(sid_str_is(&p.copy.user, expect));
        assert(p.copy.ngroups == 1);
        evict_expect_group_sid(i, expect, sizeof(expect));
        assert(sid_str_is(&p.copy.groups[0], expect));
    }

    /* Sweep back over every credential: each is either gone from the cache or
     * still holds exactly what it resolved. */
    for (i = 0; i < TEST_EVICT_N; i++) {
        const struct chimera_vfs_cred_sids *sids;

        chimera_vfs_cred_init_unix(&cred, TEST_EVICT_UID_BASE + i,
                                   TEST_EVICT_GID_BASE + i, 0, NULL);

        sids = chimera_vfs_cred_sids_lookup(thread, &cred);
        if (!sids) {
            continue;
        }

        cached++;
        evict_expect_user_sid(i, expect, sizeof(expect));
        assert(sid_str_is(&sids->user, expect));
        assert(sids->ngroups == 1);
        evict_expect_group_sid(i, expect, sizeof(expect));
        assert(sid_str_is(&sids->groups[0], expect));
    }

    /* The sweep has to have overflowed the cache, or it proved nothing. */
    assert(cached < TEST_EVICT_N);

    fprintf(stderr, "  (cache kept %d of %d credentials)\n", cached,
            TEST_EVICT_N);
    TEST_PASS("an evicting cache never answers with another credential's SIDs");
} /* test_eviction_keeps_entries_honest */

/*
 * The borrow pin.  A set handed to a callback must stay that caller's set for
 * the whole callback, even if the callback resolves something else -- the shape
 * a per-request funnel has when it warms every credential it sees.
 *
 * Without the pin the entry is quiescent while its own callback runs, so it is
 * an eligible eviction victim; a nested cold resolve landing in the same full
 * bucket repurposes it (intern() memsets it before it issues a single lookup,
 * so the clobber does not even need the nested resolve to complete).  The
 * borrowed set then changes identity under the callback's feet.
 *
 * Both routes that hand out a set are exercised: the fan-out join for a cold
 * resolve, and the warm shortcut for an already-cached one.
 */
struct pin_probe {
    struct chimera_vfs_thread *thread;
    int                        index;      /* which credential is borrowed */
    int                        nest_index; /* the one to resolve underneath */
    int                        done;
    int                        saw_set;
};

static int pin_mismatch;
static int pin_nested_outstanding;

static void
pin_nested_cb(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data)
{
    (void) sids;
    (void) private_data;
    pin_nested_outstanding--;
} /* pin_nested_cb */

static void
pin_cb(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data)
{
    struct pin_probe       *p = private_data;
    struct chimera_vfs_cred nested;
    char                    expect[CHIMERA_SID_STR_MAX];

    p->done = 1;

    if (!sids) {
        return;
    }
    p->saw_set = 1;

    /* Still holding the borrowed set, resolve an unrelated credential.  It is
     * one nothing names, so it interns an entry (the eviction pressure this
     * needs) and then parks. */
    chimera_vfs_cred_init_unix(&nested,
                               TEST_NEST_UID_BASE + p->nest_index,
                               TEST_NEST_GID_BASE + p->nest_index, 0, NULL);
    pin_nested_outstanding++;
    chimera_vfs_cred_resolve_sids(p->thread, &nested, pin_nested_cb, NULL);

    /* The pin must have held: this is still the set we were handed. */
    evict_expect_user_sid(p->index, expect, sizeof(expect));
    if (!sid_str_is(&sids->user, expect)) {
        pin_mismatch++;
    }
} /* pin_cb */

static void
test_borrow_pinned_across_callback(
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct chimera_vfs_cred cred;
    struct pin_probe        p;
    int                     i, idx, cold_sets = 0, warm_sets = 0;

    for (i = 0; i < TEST_PIN_N; i++) {
        idx = TEST_PIN_FIRST + i;
        chimera_vfs_cred_init_unix(&cred, TEST_EVICT_UID_BASE + idx,
                                   TEST_EVICT_GID_BASE + idx, 0, NULL);

        /* First resolve: cold, so the set arrives from the fan-out join. */
        memset(&p, 0, sizeof(p));
        p.thread     = thread;
        p.index      = idx;
        p.nest_index = 2 * i;
        chimera_vfs_cred_resolve_sids(thread, &cred, pin_cb, &p);
        while (!p.done) {
            evpl_continue(evpl);
        }
        cold_sets += p.saw_set;

        /* Second resolve: the entry is valid now, so the set arrives from the
         * warm shortcut instead -- a different hand-out path, same rule. */
        memset(&p, 0, sizeof(p));
        p.thread     = thread;
        p.index      = idx;
        p.nest_index = 2 * i + 1;
        chimera_vfs_cred_resolve_sids(thread, &cred, pin_cb, &p);
        while (!p.done) {
            evpl_continue(evpl);
        }
        warm_sets += p.saw_set;
    }

    /* Drain the nested resolves so nothing is left parked at teardown. */
    while (pin_nested_outstanding > 0) {
        evpl_continue(evpl);
    }

    assert(cold_sets == TEST_PIN_N);
    assert(warm_sets == TEST_PIN_N);
    assert(pin_mismatch == 0);

    TEST_PASS("a borrowed set survives a resolve started from its own callback");
} /* test_borrow_pinned_across_callback */

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
    test_eviction_keeps_entries_honest(vfs, thread, evpl);
    test_borrow_pinned_across_callback(thread, evpl);

    chimera_vfs_thread_destroy(thread);
    chimera_vfs_destroy(vfs);
    evpl_destroy(evpl);
    prometheus_metrics_destroy(metrics);

    fprintf(stderr, "All credential SID resolver tests passed!\n");
    return 0;
} /* main */
