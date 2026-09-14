// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include <string.h>

#include "vfs.h"
#include "vfs_internal.h"
#include "vfs_identity.h"
#include "vfs_cred_sids.h"
#include "sdk/vfs_sid.h"
#include "common/macros.h"

/* Distinct credentials a thread remembers.  One entry per authenticated
 * caller, so a handful covers a busy server; the cache is a plain bounded
 * chain per bucket with the oldest entry in a bucket evicted on insert. */
#define CHIMERA_VFS_CRED_SIDS_BUCKETS 64
#define CHIMERA_VFS_CRED_SIDS_CHAIN   4

struct chimera_vfs_cred_sids_entry {
    struct chimera_vfs_cred_sids_entry *next;
    uint64_t                            hash;
    int                                 valid;
    /* Resolves still filling this entry.  One with lookups outstanding must
     * not be recycled under a different credential: their contexts hold it by
     * pointer and would publish this caller's SIDs under the other's hash. */
    uint32_t                            inflight;
    struct chimera_vfs_cred_sids        sids;
};

struct chimera_vfs_cred_sids_cache {
    struct chimera_vfs_cred_sids_entry *buckets[CHIMERA_VFS_CRED_SIDS_BUCKETS];
};

/* One outstanding identity lookup within a resolve: which slot it fills. */
struct chimera_vfs_cred_sids_slot {
    struct chimera_vfs_cred_sids_ctx *ctx;
    int                               index; /* -1 = the user SID */
};

struct chimera_vfs_cred_sids_ctx {
    struct chimera_vfs_thread          *thread;
    struct chimera_vfs_cred_sids_entry *entry;
    uint32_t                            pending;
    chimera_vfs_cred_sids_callback      callback;
    void                               *private_data;
    struct chimera_vfs_cred_sids_slot   slots[CHIMERA_VFS_CRED_MAX_GIDS + 2];
};

static struct chimera_vfs_cred_sids_entry *
chimera_vfs_cred_sids_find(
    struct chimera_vfs_thread *thread,
    uint64_t                   hash)
{
    struct chimera_vfs_cred_sids_entry *entry;

    if (!thread->cred_sids) {
        return NULL;
    }

    entry = thread->cred_sids->buckets[hash % CHIMERA_VFS_CRED_SIDS_BUCKETS];

    while (entry) {
        if (entry->hash == hash) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
} /* chimera_vfs_cred_sids_find */

/*
 * Get or create the entry for `hash`.  A new entry starts invalid: a concurrent
 * lookup must not see a half-built set, and a resolve that names nothing leaves
 * it invalid so the next attempt retries (the identity layer's negative cache
 * is what keeps that retry cheap).
 */
static struct chimera_vfs_cred_sids_entry *
chimera_vfs_cred_sids_intern(
    struct chimera_vfs_thread *thread,
    uint64_t                   hash)
{
    struct chimera_vfs_cred_sids_entry *entry, *victim, *keep;
    unsigned int                        b;
    int                                 n = 0;

    if (!thread->cred_sids) {
        thread->cred_sids = calloc(1, sizeof(*thread->cred_sids));
    }

    entry = chimera_vfs_cred_sids_find(thread, hash);
    if (entry) {
        return entry;
    }

    b      = hash % CHIMERA_VFS_CRED_SIDS_BUCKETS;
    victim = NULL;

    for (entry = thread->cred_sids->buckets[b]; entry; entry = entry->next) {
        /* The last entry in the chain that no resolve is still filling: the
         * least recently interned one that is safe to repurpose. */
        if (entry->inflight == 0) {
            victim = entry;
        }
        n++;
    }

    /* Bucket full: reuse that entry in place, keeping it linked where it is.
     * Safe because a borrowed set never outlives its callback, and no resolve
     * can start while another's callback is running on this single-threaded
     * loop.  If every entry in the chain is still being resolved there is
     * nothing to reuse, so the chain grows past the bound until they finish. */
    if (n >= CHIMERA_VFS_CRED_SIDS_CHAIN && victim) {
        keep = victim->next;
        memset(victim, 0, sizeof(*victim));
        victim->next = keep;
        victim->hash = hash;
        return victim;
    }

    entry       = calloc(1, sizeof(*entry));
    entry->hash = hash;
    entry->next = thread->cred_sids->buckets[b];

    thread->cred_sids->buckets[b] = entry;

    return entry;
} /* chimera_vfs_cred_sids_intern */

/* Fan-out join: the last outstanding lookup publishes the set and continues. */
static void
chimera_vfs_cred_sids_decr(struct chimera_vfs_cred_sids_ctx *ctx)
{
    struct chimera_vfs_cred_sids_entry *entry;
    chimera_vfs_cred_sids_callback      callback;
    void                               *private_data;
    int                                 any;

    if (--ctx->pending != 0) {
        return;
    }

    entry        = ctx->entry;
    callback     = ctx->callback;
    private_data = ctx->private_data;

    /* A set with nothing in it is reported as no set at all, so a caller can
     * tell "this caller has no native identity" from "this caller is alice". */
    any = chimera_sid_present(&entry->sids.user);
    for (uint32_t i = 0; !any && i < entry->sids.ngroups; i++) {
        any = chimera_sid_present(&entry->sids.groups[i]);
    }

    entry->valid = any;
    entry->inflight--;

    free(ctx);

    callback(any ? &entry->sids : NULL, private_data);
} /* chimera_vfs_cred_sids_decr */

static void
chimera_vfs_cred_sids_resolve_cb(
    const struct chimera_vfs_identity_result *result,
    void                                     *private_data)
{
    struct chimera_vfs_cred_sids_slot *slot = private_data;
    struct chimera_vfs_cred_sids_ctx  *ctx  = slot->ctx;
    struct chimera_sid                *dst;
    const char                        *sidstr;

    if (result) {
        sidstr = result->is_group ? result->group.sid : result->user.sid;

        if (sidstr && sidstr[0]) {
            dst = (slot->index < 0) ? &ctx->entry->sids.user
                                    : &ctx->entry->sids.groups[slot->index];
            /* A malformed SID from a handler leaves the slot absent, which is
             * the same as unresolved: it matches nobody. */
            if (chimera_sid_from_str(dst, sidstr) != 0) {
                memset(dst, 0, sizeof(*dst));
            }
        }
    }

    chimera_vfs_cred_sids_decr(ctx);
} /* chimera_vfs_cred_sids_resolve_cb */

SYMBOL_EXPORT const struct chimera_vfs_cred_sids *
chimera_vfs_cred_sids_lookup(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred)
{
    struct chimera_vfs_cred_sids_entry *entry;

    entry = chimera_vfs_cred_sids_find(thread, chimera_vfs_cred_hash(cred));

    return (entry && entry->valid) ? &entry->sids : NULL;
} /* chimera_vfs_cred_sids_lookup */

SYMBOL_EXPORT void
chimera_vfs_cred_resolve_sids(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred,
    chimera_vfs_cred_sids_callback callback,
    void                          *private_data)
{
    struct chimera_vfs_cred_sids_entry *entry;
    struct chimera_vfs_cred_sids_ctx   *ctx;
    uint64_t                            hash;
    uint32_t                            i, nslots;

    hash  = chimera_vfs_cred_hash(cred);
    entry = chimera_vfs_cred_sids_find(thread, hash);

    /* Warm: no allocation, no lookup, no park. */
    if (entry && entry->valid) {
        callback(&entry->sids, private_data);
        return;
    }

    entry = chimera_vfs_cred_sids_intern(thread, hash);

    /* Only reset an entry nothing else is filling.  A resolve already running
     * on this credential is writing the same slots from the same ids, so
     * joining it in place is idempotent, where clearing under it would discard
     * what it has already resolved. */
    if (entry->inflight == 0) {
        memset(&entry->sids, 0, sizeof(entry->sids));
        entry->valid = 0;

        /* groups[] is the primary gid followed by the supplementary ones, in
         * the order the credential carries them, so a slot index maps straight
         * back to the gid it came from. */
        entry->sids.ngroups = 1 + cred->ngids;
        if (entry->sids.ngroups > CHIMERA_VFS_CRED_MAX_GIDS + 1) {
            entry->sids.ngroups = CHIMERA_VFS_CRED_MAX_GIDS + 1;
        }
    }

    entry->inflight++;

    ctx               = calloc(1, sizeof(*ctx));
    ctx->thread       = thread;
    ctx->entry        = entry;
    ctx->callback     = callback;
    ctx->private_data = private_data;
    ctx->pending      = 1; /* guard until every lookup is issued */

    nslots = 0;

    ctx->slots[nslots].ctx   = ctx;
    ctx->slots[nslots].index = -1;
    ctx->pending++;
    chimera_vfs_identity_resolve(thread, CHIMERA_VFS_IDENTITY_BY_UID,
                                 cred->uid, NULL,
                                 chimera_vfs_cred_sids_resolve_cb,
                                 &ctx->slots[nslots]);
    nslots++;

    for (i = 0; i < entry->sids.ngroups; i++) {
        uint32_t gid = (i == 0) ? cred->gid : cred->gids[i - 1];

        ctx->slots[nslots].ctx   = ctx;
        ctx->slots[nslots].index = (int) i;
        ctx->pending++;
        chimera_vfs_identity_resolve(thread, CHIMERA_VFS_IDENTITY_BY_GID,
                                     gid, NULL,
                                     chimera_vfs_cred_sids_resolve_cb,
                                     &ctx->slots[nslots]);
        nslots++;
    }

    /* Drop the guard.  Every lookup that hit the cache has already fired its
     * callback inline, so this is what completes an all-warm resolve. */
    chimera_vfs_cred_sids_decr(ctx);
} /* chimera_vfs_cred_resolve_sids */

static void
chimera_vfs_cred_sids_warm_cb(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data)
{
    (void) sids;
    (void) private_data;
} /* chimera_vfs_cred_sids_warm_cb */

SYMBOL_EXPORT void
chimera_vfs_cred_sids_warm(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred)
{
    chimera_vfs_cred_resolve_sids(thread, cred,
                                  chimera_vfs_cred_sids_warm_cb, NULL);
} /* chimera_vfs_cred_sids_warm */

SYMBOL_EXPORT void
chimera_vfs_cred_sids_thread_destroy(struct chimera_vfs_thread *thread)
{
    struct chimera_vfs_cred_sids_entry *entry, *next;

    if (!thread->cred_sids) {
        return;
    }

    for (int b = 0; b < CHIMERA_VFS_CRED_SIDS_BUCKETS; b++) {
        entry = thread->cred_sids->buckets[b];
        while (entry) {
            next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(thread->cred_sids);
    thread->cred_sids = NULL;
} /* chimera_vfs_cred_sids_thread_destroy */
