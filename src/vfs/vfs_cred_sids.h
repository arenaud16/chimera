// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * Credential SID resolver: maps a credential to the native Windows SIDs that
 * describe it -- its own user SID plus one per group it belongs to -- so ACL
 * evaluation can match an ACE carrying a bare domain SID against the caller
 * (see cred_matches_sid in vfs_acl.c).
 *
 * This is the caller-side half of the dual identity.  Resolving the caller
 * once is O(1 + ngids) per credential, where resolving each ACE would be
 * O(ACEs) per access and would have to copy and rewrite an ACL that belongs to
 * the backend.
 *
 * Results are cached per VFS thread, keyed by chimera_vfs_cred_hash() and
 * confirmed against the credential itself, so a repeat caller resolves with no
 * lock and no allocation.
 *
 * A returned set is BORROWED from that cache, which reuses its entries once a
 * hash bucket fills.  How long the borrow lasts depends on how it was obtained:
 *
 *   - A set handed to a chimera_vfs_cred_sids_callback is pinned for the
 *     duration of that callback.  It stays valid even if the callback resolves
 *     another credential, so it is always safe to read and to copy there.
 *
 *   - A set returned by chimera_vfs_cred_sids_probe() (or its
 *     chimera_vfs_cred_sids_lookup() shorthand) is pinned by nothing.
 *     It is valid only until this thread next calls
 *     chimera_vfs_cred_resolve_sids() or chimera_vfs_cred_sids_warm(), and
 *     never past the current trip through the event loop.
 *
 * Copy it if it must live longer (an SMB session does exactly that).
 */

#include "sdk/vfs_cred.h"

struct chimera_vfs_thread;

typedef void (*chimera_vfs_cred_sids_callback)(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data);

/*
 * Resolve `cred` to its SID set.  On a warm cache the callback fires inline,
 * before this returns; otherwise it fires later on `thread`'s evpl loop.
 * `sids` is NULL when nothing about the caller could be resolved, and is
 * pinned for the duration of the callback otherwise.  A NULL `cred` (an
 * internal/server operation, which carries no identity) is answered the same
 * way, inline, as is a NULL `cred` passed to any other entry point here.
 */
void
chimera_vfs_cred_resolve_sids(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred,
    chimera_vfs_cred_sids_callback callback,
    void                          *private_data);

/*
 * Synchronous probe for a path that cannot park (the per-request NFS
 * credential funnel, a readdir entry callback).  Never resolves and never
 * blocks.
 *
 * Reports two things, because a caller needs both:
 *
 *   - the return value is non-zero when this thread already has an answer for
 *     `cred`, or has one on the way, so there is no point starting a resolve.
 *     Zero means nobody has asked lately: the caller proceeds with what it has
 *     and warms the cache for its next request.
 *
 *   - `*sids` is the cached set, or NULL when the credential resolved to no
 *     native identity at all -- the ordinary case on a deployment with no SID
 *     source, where a resolve completes, names nothing, and must not be
 *     retried for every subsequent request.
 *
 * A set whose TTL has run out is still handed back while its replacement is
 * being resolved; expiry triggers a refresh rather than an invalidation, so a
 * caller is never transiently unresolved (and, on a path that proceeds on a
 * miss, transiently denied) just because the clock rolled over.
 *
 * The result is unpinned -- see the borrow rules above.  Use it, or copy it,
 * before starting another resolve on this thread.
 */
int
chimera_vfs_cred_sids_probe(
    struct chimera_vfs_thread           *thread,
    const struct chimera_vfs_cred       *cred,
    const struct chimera_vfs_cred_sids **sids);

/*
 * The set half of chimera_vfs_cred_sids_probe(), for callers that only want to
 * read what is cached and have nothing to warm.
 */
const struct chimera_vfs_cred_sids *
chimera_vfs_cred_sids_lookup(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred);

/*
 * Start resolving `cred` and discard the result -- it lands in this thread's
 * cache, so a later chimera_vfs_cred_sids_lookup() finds it.  Used by callers
 * that cannot park: they proceed unresolved once, and are enforced from the
 * next request on.
 */
void
chimera_vfs_cred_sids_warm(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred);

/*
 * Override how long this thread trusts a completed resolve, in seconds.
 *
 * The default is a minute, matching the identity caches underneath (see
 * CHIMERA_VFS_CRED_SIDS_TTL).  The server leaves it alone; this exists so the
 * unit test can exercise expiry and re-resolution without waiting one.
 */
void
chimera_vfs_cred_sids_set_ttl(
    struct chimera_vfs_thread *thread,
    uint32_t                   seconds);

/* Free a thread's credential-SID cache (called from VFS thread teardown). */
void
chimera_vfs_cred_sids_thread_destroy(
    struct chimera_vfs_thread *thread);
