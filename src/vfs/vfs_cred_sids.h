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
 * Results are cached per VFS thread, keyed by chimera_vfs_cred_hash(), so a
 * repeat caller resolves with no lock and no allocation.  A returned set is
 * BORROWED: it is valid until the calling thread returns to its event loop.
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
 * `sids` is NULL when nothing about the caller could be resolved.
 */
void
chimera_vfs_cred_resolve_sids(
    struct chimera_vfs_thread     *thread,
    const struct chimera_vfs_cred *cred,
    chimera_vfs_cred_sids_callback callback,
    void                          *private_data);

/*
 * Synchronous probe: the cached SID set for `cred` on this thread, or NULL.
 * Never resolves and never blocks, so it is safe on a path that cannot park
 * (the per-request NFS credential funnel, a readdir entry callback).
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

/* Free a thread's credential-SID cache (called from VFS thread teardown). */
void
chimera_vfs_cred_sids_thread_destroy(
    struct chimera_vfs_thread *thread);
