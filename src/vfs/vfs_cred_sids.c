// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/*
 * How long a completed resolve is trusted, in seconds.
 *
 * This cache is layered over two that already expire: chimera_vfs_user_cache
 * ages its users and groups out on a 60-second sweep, and vfs_identity.c
 * remembers an id nothing could name for CHIMERA_VFS_IDENTITY_NEGATIVE_TTL,
 * also 60 seconds.  An untimed layer on top of those throws that property
 * away -- a resolve that came back partial because one group lookup happened
 * to hiccup (and the negative cache guarantees the hiccup is remembered for a
 * while) would otherwise be the answer for the rest of the thread's life, with
 * the caller silently losing every access that group SID grants.
 *
 * Matching the layer below is what makes the retry worth taking: by the time
 * an entry expires, the negative that spoiled it has expired too, so the
 * re-resolve asks the handlers again rather than replaying the same refusal.
 */
#define CHIMERA_VFS_CRED_SIDS_TTL     60

struct chimera_vfs_cred_sids_entry {
    struct chimera_vfs_cred_sids_entry *next;
    uint64_t                            hash;
    /* Two distinct facts, because the callers need to tell them apart.
     * `resolved`: a resolve ran to completion for this credential, whatever it
     * found -- a caller that cannot park (the NFS per-request funnel) tests
     * this to decide whether starting one is worth it, and a deployment with
     * no SID source at all would otherwise re-fan-out 1 + ngids lookups on
     * every single request forever.  `valid`: that resolve named at least one
     * SID, so there is a set worth handing out.  `expiration` ages both out;
     * see CHIMERA_VFS_CRED_SIDS_TTL. */
    int                                 resolved;
    int                                 valid;
    uint64_t                            expiration;
    /* Resolves still filling this entry, plus the callback each of them is
     * running.  An entry with either outstanding must not be recycled under a
     * different credential: a resolve holds it by pointer and would publish
     * this caller's SIDs under the other's hash, and a callback is reading the
     * very set it was handed. */
    uint32_t                            inflight;
    /* The credential this entry describes, compared in full on a hash match.
     * chimera_vfs_cred_hash() tolerates collisions because the open-handle
     * cache it was written for merely shares a handle on one; here a collision
     * would answer one caller's access check with another caller's SIDs, so
     * the hash only selects a candidate and these fields decide. */
    enum chimera_vfs_cred_flavor        flavor;
    uint32_t                            uid;
    uint32_t                            gid;
    uint32_t                            ngids;
    uint32_t                            gids[CHIMERA_VFS_CRED_MAX_GIDS];
    struct chimera_vfs_cred_sids        sids;
};

struct chimera_vfs_cred_sids_cache {
    uint32_t                            ttl;
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
    /* The set being built.  A resolve fills its OWN set and moves it into the
     * entry whole at the join, rather than writing through to the entry as it
     * goes.  The entry therefore keeps answering with whatever it last
     * published until the replacement is complete: a refresh at the end of the
     * TTL never leaves a caller transiently unresolved (which, on a path that
     * proceeds on a miss, means transiently denied), and two resolves running
     * on the same entry cannot show each other's half-built work. */
    struct chimera_vfs_cred_sids        set;
    struct chimera_vfs_cred_sids_slot   slots[CHIMERA_VFS_CRED_MAX_GIDS + 2];
};

/*
 * Supplementary gids of `cred` that are actually addressable.
 *
 * ngids is a plain uint32_t on an SDK struct, and gids[] is
 * CHIMERA_VFS_CRED_MAX_GIDS long: an out-of-tree module that sets a larger
 * count (no in-tree constructor does) would otherwise turn a read past the end
 * of the caller's array into a write past the end of a cache entry's.  Clamp
 * every walk of the array; the unclamped count is still what decides identity,
 * so two credentials that differ only above the clamp stay distinct entries.
 */
static inline uint32_t
chimera_vfs_cred_sids_ngids(const struct chimera_vfs_cred *cred)
{
    return cred->ngids > CHIMERA_VFS_CRED_MAX_GIDS ?
           CHIMERA_VFS_CRED_MAX_GIDS : cred->ngids;
} /* chimera_vfs_cred_sids_ngids */

/* Does `entry` describe exactly `cred`?  Every field the hash mixes, compared
 * directly; only the first `ngids` supplementary gids are meaningful. */
static int
chimera_vfs_cred_sids_key_eq(
    const struct chimera_vfs_cred_sids_entry *entry,
    const struct chimera_vfs_cred            *cred)
{
    if (entry->flavor != cred->flavor ||
        entry->uid != cred->uid ||
        entry->gid != cred->gid ||
        entry->ngids != cred->ngids) {
        return 0;
    }

    return memcmp(entry->gids, cred->gids,
                  chimera_vfs_cred_sids_ngids(cred) *
                  sizeof(cred->gids[0])) == 0;
} /* chimera_vfs_cred_sids_key_eq */

static void
chimera_vfs_cred_sids_set_key(
    struct chimera_vfs_cred_sids_entry *entry,
    const struct chimera_vfs_cred      *cred,
    uint64_t                            hash)
{
    entry->hash   = hash;
    entry->flavor = cred->flavor;
    entry->uid    = cred->uid;
    entry->gid    = cred->gid;
    entry->ngids  = cred->ngids;
    memcpy(entry->gids, cred->gids,
           chimera_vfs_cred_sids_ngids(cred) * sizeof(cred->gids[0]));
} /* chimera_vfs_cred_sids_set_key */

/* Coarse monotonic seconds; entry expiry is the only thing that reads it. */
static inline uint64_t
chimera_vfs_cred_sids_now(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t) ts.tv_sec;
} /* chimera_vfs_cred_sids_now */

/* This thread's cache, created on first use. */
static inline struct chimera_vfs_cred_sids_cache *
chimera_vfs_cred_sids_cache(struct chimera_vfs_thread *thread)
{
    if (!thread->cred_sids) {
        thread->cred_sids      = calloc(1, sizeof(*thread->cred_sids));
        thread->cred_sids->ttl = CHIMERA_VFS_CRED_SIDS_TTL;
    }

    return thread->cred_sids;
} /* chimera_vfs_cred_sids_cache */

/* Has a resolve completed for this entry, recently enough to still believe? */
static inline int
chimera_vfs_cred_sids_fresh(
    const struct chimera_vfs_cred_sids_entry *entry,
    uint64_t                                  now)
{
    return entry->resolved && now < entry->expiration;
} /* chimera_vfs_cred_sids_fresh */

/*
 * Bucket index for a credential hash.
 *
 * chimera_vfs_cred_hash() is a word-wise FNV-1a over flavor, uid, gid and the
 * supplementary gids.  Three or four multiplies is not enough to avalanche it:
 * the low bits of a product depend only on the low bits of its operands, so
 * uid and gid moving in step (the ubiquitous user-private-group layout, uid ==
 * gid) largely cancel there, and the high bits of the accumulator barely move
 * at all for realistic id ranges.  Indexing off either end therefore piles
 * every caller into a handful of buckets: measured over 400 sequential
 * uid/gid pairs, the low six bits reach 13 of the 64 buckets and the cache
 * retains 52 of a nominal 256 entries.  That is not merely a performance
 * matter here -- the NFS funnel proceeds unenforced on a miss, so a table that
 * evicts between requests makes the same operation by the same caller
 * enforced or not depending on cache state.
 *
 * Avalanche the hash first (the murmur3 64-bit finalizer) so every input bit
 * reaches the index.  The same 400 pairs then reach all 64 buckets and retain
 * 243 entries.  A fold of the high half onto the low one is NOT enough: bits
 * 32-37 of the FNV accumulator are constant across such a sweep, so it lands
 * on exactly the 13 buckets the low bits alone do.
 */
static inline unsigned int
chimera_vfs_cred_sids_bucket(uint64_t hash)
{
    hash ^= hash >> 33;
    hash *= 0xff51afd7ed558ccdULL;
    hash ^= hash >> 33;
    hash *= 0xc4ceb9fe1a85ec53ULL;
    hash ^= hash >> 33;

    return (unsigned int) (hash % CHIMERA_VFS_CRED_SIDS_BUCKETS);
} /* chimera_vfs_cred_sids_bucket */

static struct chimera_vfs_cred_sids_entry *
chimera_vfs_cred_sids_find(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred,
    uint64_t                       hash)
{
    struct chimera_vfs_cred_sids_entry *entry;

    /* A credential-less (internal/server) operation has no identity to
     * resolve, so nothing is ever interned for one and there is nothing here
     * to find either.  Every entry point in this file takes NULL the same way:
     * no set, no crash (see chimera_vfs_cred_resolve_sids). */
    if (!cred || !thread->cred_sids) {
        return NULL;
    }

    entry = thread->cred_sids->buckets[chimera_vfs_cred_sids_bucket(hash)];

    while (entry) {
        if (entry->hash == hash &&
            chimera_vfs_cred_sids_key_eq(entry, cred)) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
} /* chimera_vfs_cred_sids_find */

/*
 * Get or create the entry for `hash`.  A new entry starts neither resolved nor
 * valid: a lookup must not see a half-built set, and a resolve that names
 * nothing publishes itself as resolved-but-not-valid, which is the answer a
 * caller that cannot park needs in order to stop asking for it (until the
 * entry expires and the question is worth asking again).
 */
static struct chimera_vfs_cred_sids_entry *
chimera_vfs_cred_sids_intern(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred,
    uint64_t                       hash)
{
    struct chimera_vfs_cred_sids_entry *entry, *victim, *keep;
    unsigned int                        b;
    int                                 n = 0;

    chimera_vfs_cred_sids_cache(thread);

    entry = chimera_vfs_cred_sids_find(thread, cred, hash);
    if (entry) {
        return entry;
    }

    b      = chimera_vfs_cred_sids_bucket(hash);
    victim = NULL;

    for (entry = thread->cred_sids->buckets[b]; entry; entry = entry->next) {
        /* The last entry in the chain with inflight == 0: the least recently
         * interned one that is safe to repurpose. */
        if (entry->inflight == 0) {
            victim = entry;
        }
        n++;
    }

    /* Bucket full: reuse that entry in place, keeping it linked where it is.
     *
     * `inflight` is the whole of the invariant.  Non-zero means either a
     * resolve is still filling the entry (its context and its outstanding
     * lookups hold it by pointer) or a callback is reading the set it was just
     * handed; repurposing it in either state would publish one caller's SIDs
     * under another caller's key.  Zero means nothing holds it and stamping a
     * new credential on it is safe.  Note this is NOT implied by callbacks
     * running to completion on a single-threaded loop: a parked resolve spans
     * many trips round that loop, and other resolves start meanwhile.
     *
     * If every entry in the chain is held there is nothing to reuse, so the
     * chain grows past the bound.  It does not shrink back: nothing outside
     * chimera_vfs_cred_sids_thread_destroy() ever frees an entry, so a chain's
     * high-water length is permanent for the life of the thread.  Entries past
     * the bound are recycled like any other once their holders drop, so this
     * costs memory, not correctness. */
    if (n >= CHIMERA_VFS_CRED_SIDS_CHAIN && victim) {
        keep = victim->next;
        memset(victim, 0, sizeof(*victim));
        victim->next = keep;
        chimera_vfs_cred_sids_set_key(victim, cred, hash);
        return victim;
    }

    entry       = calloc(1, sizeof(*entry));
    entry->next = thread->cred_sids->buckets[b];
    chimera_vfs_cred_sids_set_key(entry, cred, hash);

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
    any = chimera_sid_present(&ctx->set.user);
    for (uint32_t i = 0; !any && i < ctx->set.ngroups; i++) {
        any = chimera_sid_present(&ctx->set.groups[i]);
    }

    /* Publish the outcome in one move: resolved either way -- that is what
     * tells a caller which cannot park that asking again is pointless --
     * valid only if it named something, and both believed until the TTL runs
     * out.  A refresh that comes back with less than the last one replaces it
     * rather than leaving the old grant standing. */
    entry->sids       = ctx->set;
    entry->valid      = any;
    entry->resolved   = 1;
    entry->expiration = chimera_vfs_cred_sids_now() +
        ctx->thread->cred_sids->ttl;

    free(ctx);

    callback(any ? &entry->sids : NULL, private_data);

    /* Unpinned only now.  For the duration of the callback the entry is still
     * held -- by the very set just handed out -- and dropping the pin above
     * would make it an eligible eviction victim while the callback reads it.
     * That is reachable: a callback may start a cold resolve of its own (the
     * per-request funnel warms every credential it sees), and if that lands in
     * this full bucket and completes inline, the borrowed set would turn into
     * another caller's before the callback returned. */
    entry->inflight--;
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
            dst = (slot->index < 0) ? &ctx->set.user
                                    : &ctx->set.groups[slot->index];
            /* A malformed SID from a handler leaves the slot absent, which is
             * the same as unresolved: it matches nobody. */
            if (chimera_sid_from_str(dst, sidstr) != 0) {
                memset(dst, 0, sizeof(*dst));
            }
        }
    }

    chimera_vfs_cred_sids_decr(ctx);
} /* chimera_vfs_cred_sids_resolve_cb */

SYMBOL_EXPORT int
chimera_vfs_cred_sids_probe(
    struct chimera_vfs_thread           *thread,
    const struct chimera_vfs_cred       *cred,
    const struct chimera_vfs_cred_sids **sids)
{
    struct chimera_vfs_cred_sids_entry *entry;

    *sids = NULL;

    entry = chimera_vfs_cred_sids_find(thread, cred,
                                       chimera_vfs_cred_hash(cred));

    if (!entry) {
        return 0;
    }

    /* Whatever this entry last published is handed out even once it is past
     * its TTL: expiry is a refresh trigger, not an invalidation.  Withholding
     * the set until the refresh lands would leave this caller unenforced --
     * on the NFS funnel, denied -- for every request in that window, once per
     * TTL.  A refresh replaces the set whole, so nothing served here is ever
     * older than one TTL plus one resolve. */
    if (entry->valid) {
        *sids = &entry->sids;
    }

    if (chimera_vfs_cred_sids_fresh(entry, chimera_vfs_cred_sids_now())) {
        return 1;
    }

    /* Never resolved, or resolved too long ago to believe, so the caller
     * should start one -- unless one is already running, which counts as an
     * answer on its way.  That is also what stops the requests arriving while
     * a caller's first resolve is parked from each stacking a 1 + ngids
     * fan-out of their own. */
    return entry->inflight != 0;
} /* chimera_vfs_cred_sids_probe */

SYMBOL_EXPORT const struct chimera_vfs_cred_sids *
chimera_vfs_cred_sids_lookup(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred)
{
    const struct chimera_vfs_cred_sids *sids;

    chimera_vfs_cred_sids_probe(thread, cred, &sids);

    return sids;
} /* chimera_vfs_cred_sids_lookup */

SYMBOL_EXPORT void
chimera_vfs_cred_sids_set_ttl(
    struct chimera_vfs_thread *thread,
    uint32_t                   seconds)
{
    chimera_vfs_cred_sids_cache(thread)->ttl = seconds;
} /* chimera_vfs_cred_sids_set_ttl */

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

    /* An operation with no credential (internal/server work, which the engine
     * exempts from enforcement anyway) has nothing to resolve.  Answer it the
     * way an unnameable caller is answered -- no set -- rather than faulting
     * on it in chimera_vfs_cred_sids_intern(), so that NULL means the same
     * thing at every entry point here. */
    if (!cred) {
        callback(NULL, private_data);
        return;
    }

    hash  = chimera_vfs_cred_hash(cred);
    entry = chimera_vfs_cred_sids_find(thread, cred, hash);

    /* Warm: no allocation, no lookup, no park.  Pinned across the callback for
     * the same reason the cold path is -- the callback holds the set, and a
     * resolve it starts of its own must not evict it underneath.
     *
     * An entry past its TTL falls through to the cold path instead, which
     * re-resolves it in place: that is how a set that came back partial (or
     * empty) because the identity layer was having a bad minute heals itself
     * rather than standing for the life of the thread. */
    if (entry && entry->valid &&
        chimera_vfs_cred_sids_fresh(entry, chimera_vfs_cred_sids_now())) {
        entry->inflight++;
        callback(&entry->sids, private_data);
        entry->inflight--;
        return;
    }

    entry = chimera_vfs_cred_sids_intern(thread, cred, hash);

    /* The entry is the destination, not the workspace: this resolve builds its
     * set in its own context and moves it in at the join.  Nothing here
     * disturbs what the entry is currently answering with, and a resolve
     * already running on this entry (necessarily on the same credential -- the
     * key is compared in full) neither sees nor is seen by this one. */
    entry->inflight++;

    ctx               = calloc(1, sizeof(*ctx));
    ctx->thread       = thread;
    ctx->entry        = entry;
    ctx->callback     = callback;
    ctx->private_data = private_data;
    ctx->pending      = 1; /* guard until every lookup is issued */

    /* groups[] is the primary gid followed by the supplementary ones, in the
     * order the credential carries them, so a slot index maps straight back to
     * the gid it came from. */
    ctx->set.ngroups = 1 + chimera_vfs_cred_sids_ngids(cred);

    nslots = 0;

    ctx->slots[nslots].ctx   = ctx;
    ctx->slots[nslots].index = -1;
    ctx->pending++;
    chimera_vfs_identity_resolve(thread, CHIMERA_VFS_IDENTITY_BY_UID,
                                 cred->uid, NULL,
                                 chimera_vfs_cred_sids_resolve_cb,
                                 &ctx->slots[nslots]);
    nslots++;

    for (i = 0; i < ctx->set.ngroups; i++) {
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
