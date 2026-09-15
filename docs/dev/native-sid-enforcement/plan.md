# Resolve CHIMERA_PRINCIPAL_SID on the access path

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a DACL whose ACEs carry only native Windows SIDs actually enforce, by giving every credential the set of SIDs that describe it and comparing ACE SIDs against that set.

**Architecture:** Instead of resolving each ACE's SID to a uid/gid (the direction the ticket proposes), resolve the *caller* once to its native SID set -- its own user SID plus one SID per group it belongs to -- and attach that set to `struct chimera_vfs_cred` by pointer. `ace_applies()` then answers a `CHIMERA_PRINCIPAL_SID` ACE with a byte comparison against that set. Because every access-check site (the VFS gate, the four `vfs_proc_*` checks, both NFS ACCESS procs, the five SMB CREATE checks, and the readdir access-based-enumeration path) borrows the credential the protocol server built, populating the set where the credential is built covers all of them with no change to any access-check call site. The stored descriptor is never read for identity resolution and never written, so it is trivially byte-identical across an access check.

**Tech Stack:** C11, libevpl event loop, liburcu QSBR, CMake/Ninja, ctest. Existing machinery reused: `chimera_vfs_identity_resolve()` (park-and-resume identity resolver), `chimera_sid_equal()` / `chimera_sid_from_str()`, `chimera_vfs_cred_hash()`.

**Spec:** the originating ticket. Read the ticket alongside this plan. This plan deliberately inverts the ticket's proposed resolution direction; see "Deviation from the spec" below.

---

## Deviation from the spec, and why

The ticket proposes resolving ACE SIDs to uid/gid and rewriting the decoded ACL. Three properties of the current code make that expensive:

1. `va_acl` is backend-owned storage, valid only for the duration of the completion callback (`src/vfs/sdk/vfs_attrs.h:233-236`), and memfs points it at the *live* inode ACL (`src/vfs/memfs/memfs.c:1613`). Rewriting principals in place would mutate stored state, breaking the ticket's own "stored descriptor is byte-identical" criterion. Every access on a SID-storing backend would therefore need an ACL copy.
2. The gate scratch area is 384 bytes (`src/vfs/sdk/vfs_request.h:433`); a 64-ACE copy is about 5.6 KB, so the copy needs new allocation machinery on a hot path.
3. Cost scales with ACE count and is worst for *unresolvable* SIDs -- exactly the Samba-migration case the ticket is about.

Resolving the caller instead is O(1 + ngids) per credential rather than O(ACEs) per access, needs no ACL copy and no mutation, and costs nothing for ACE SIDs that resolve to nothing. It was chosen deliberately by the ticket owner.

**Group membership (the ticket's third open question) is confirmed working.** The SMB server fills the credential's supplementary gids from winbind at logon (`src/server/smb/smb_proc_session_setup.c:519-527`, capped at `CHIMERA_VFS_CRED_MAX_GIDS`, which is 16), and NFS takes them from the RPC credential. So a caller's group SIDs can be derived from the gids the credential already carries, which is exactly what Task 3 does.

**Accepted consequence (NFS):** SMB builds one long-lived credential per session, so its SID set is resolved asynchronously at session setup and is always present. NFS builds a credential per request through a synchronous funnel, so it takes the SID set from a warm per-thread cache and, on a miss, kicks a background resolve and proceeds with `sids = NULL`. A never-before-seen NFS caller therefore gets today's behaviour (SID ACEs match nobody -- fail closed) on its first request and correct enforcement from the second onward. Task 5 makes this explicit and tests it.

## Global Constraints

- **ASCII only.** Every byte of every source file and comment must be in 0x00-0x7F. No em dashes, no unicode. Use `--` where prose wants a dash.
- **Formatting:** uncrustify with `etc/uncrustify.cfg`. 4-space indent, no tabs.
- **SPDX headers** required on every new file: `// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors` then `//` then `// SPDX-License-Identifier: LGPL-2.1-only`.
- **Upstream-first.** This is a topic branch off `arenaud16/main`, verified locally. Do NOT run the internal CI tool, `make check`, `make syntax`, or `make copyright` -- run individual targets and `ctest` directly.
- **Commit subjects** use an `<area>:` prefix (e.g. `vfs:`, `smb:`, `nfs:`), NOT `<ticket>:`. Scrub every CHIM reference from code comments and commit messages.
- **Every commit** ends with the trailer `Signed-off-by: Alain Renaud <alain.renaud@quantum.com>`.
- **Build commands** run under `sudo` in this environment.
- **Principal by-value contract** (`src/vfs/sdk/vfs_acl.h:145-160`): a `chimera_principal` is compared with memcmp, so every byte must be defined. Do not introduce a code path that leaves one partly initialised.
- **SDK version:** `CHIMERA_VFS_SDK_VERSION` (`src/vfs/sdk/vfs_module.h:31`) is 2. Task 1 changes an SDK struct layout and must bump it to 3.

## File Structure

**New files**

- `src/vfs/vfs_cred_sids.h` -- public interface of the credential-SID resolver: the async resolve entry point, the synchronous warm probe, and the copy helper. One responsibility: turning a credential into its SID set.
- `src/vfs/vfs_cred_sids.c` -- implementation: the per-thread cache keyed by `chimera_vfs_cred_hash()`, and the fan-out/join over `chimera_vfs_identity_resolve()`.
- `src/vfs/tests/vfs_cred_sids_test.c` -- unit coverage for the resolver: warm path resolves inline, cold path parks and resumes, unresolvable ids leave slots absent.
- `src/vfs/tests/vfs_acl_sid_enforce_test.c` -- end-to-end: an all-opaque DACL over memfs grants after resolution, an unresolvable SID denies, and the mixed case.

**Modified files**

- `src/vfs/sdk/vfs_cred.h` -- the `chimera_vfs_cred_sids` value type and the `sids` pointer on `chimera_vfs_cred`.
- `src/vfs/sdk/vfs_module.h` -- SDK version 2 -> 3.
- `src/vfs/vfs_cred.c` -- clear `sids` in the out-of-line initialisers.
- `src/vfs/vfs_acl.c` -- the `CHIMERA_PRINCIPAL_SID` arm of `ace_applies()`.
- `src/vfs/vfs_identity.c` -- negative cache and in-flight de-duplication.
- `src/vfs/CMakeLists.txt`, `src/vfs/tests/CMakeLists.txt` -- new source and tests.
- `src/server/smb/smb_session.h`, `src/server/smb/smb_proc_session_setup.c` -- resolve the session's SID set.
- `src/server/nfs/nfs_common.h` -- warm-probe the request credential's SID set.
- `src/vfs/tests/vfs_acl_test.c`, `src/vfs/tests/vfs_identity_test.c` -- unit coverage for tasks 1 and 2.

---

### Task 1: Credential SID set and the ace_applies() SID arm

This is the whole access-control change. Everything after it is plumbing to populate the set.

**Files:**
- Modify: `src/vfs/sdk/vfs_cred.h`
- Modify: `src/vfs/sdk/vfs_module.h:31`
- Modify: `src/vfs/vfs_cred.c`
- Modify: `src/vfs/vfs_acl.c:75-126` (`ace_applies`)
- Test: `src/vfs/tests/vfs_acl_test.c`

**Interfaces:**
- Produces: `struct chimera_vfs_cred_sids { uint32_t ngroups; struct chimera_sid user; struct chimera_sid groups[CHIMERA_VFS_CRED_MAX_GIDS + 1]; }` and the field `const struct chimera_vfs_cred_sids *sids` on `struct chimera_vfs_cred`. Tasks 3, 4 and 5 fill this in; nothing else reads it.
- Consumes: `chimera_sid_equal()` and `chimera_sid_present()` from `src/vfs/sdk/vfs_sid.h` (already inline, already included transitively by `vfs_acl.h`).

- [ ] **Step 1: Write the failing test**

Add to `src/vfs/tests/vfs_acl_test.c`, after the existing `mkcred` helper:

```c
/* Build a cred whose SID set contains one user SID and one group SID. */
static void
mkcred_sids(
    struct chimera_vfs_cred_sids *sids,
    const char                   *user_sid,
    const char                   *group_sid)
{
    memset(sids, 0, sizeof(*sids));

    if (user_sid) {
        assert(chimera_sid_from_str(&sids->user, user_sid) == 0);
    }
    if (group_sid) {
        assert(chimera_sid_from_str(&sids->groups[0], group_sid) == 0);
        sids->ngroups = 1;
    }
} /* mkcred_sids */

/*
 * A DACL made only of native SID ACEs enforces against a caller whose SID set
 * carries the matching SID, and matches nobody otherwise.  This is the whole
 * point of the dual identity: the ACE never names a uid, so the match has to
 * come from the caller's own SIDs.
 */
#define TEST_USER_SID  "S-1-5-21-111-222-333-1001"
#define TEST_GROUP_SID "S-1-5-21-111-222-333-513"
#define TEST_OTHER_SID "S-1-5-21-111-222-333-1002"

static void
test_opaque_sid_ace_enforces(void)
{
    ACL_BUF(acl, 4);
    struct chimera_vfs_cred      named   = mkcred(1500, 1500);
    struct chimera_vfs_cred      grpmbr  = mkcred(1501, 1501);
    struct chimera_vfs_cred      stranger = mkcred(1502, 1502);
    struct chimera_vfs_cred_sids named_sids, grp_sids, stranger_sids;
    uint32_t                     g;

    /* One ALLOW ACE naming a bare domain user SID, and nothing else. */
    memset(acl, 0, sizeof(struct chimera_acl) + 2 * sizeof(struct chimera_ace));
    acl->num_aces          = 1;
    acl->aces[0].type      = CHIMERA_ACE_ALLOWED;
    acl->aces[0].flags     = 0;
    acl->aces[0].access_mask = CHIMERA_ACE_READ_DATA | CHIMERA_ACE_WRITE_DATA;
    acl->aces[0].who.type  = CHIMERA_PRINCIPAL_SID;
    assert(chimera_sid_from_str(&acl->aces[0].who.sid, TEST_USER_SID) == 0);

    /* The caller whose user SID the ACE names is granted. */
    mkcred_sids(&named_sids, TEST_USER_SID, NULL);
    named.sids = &named_sids;
    g          = chimera_acl_access_check(acl, 0, 9999, 9999, &named,
                                          CHIMERA_ACE_READ_DATA, 0);
    assert(g == CHIMERA_ACE_READ_DATA);

    /* A caller with no SID set at all matches nothing (today's behaviour). */
    g = chimera_acl_access_check(acl, 0, 9999, 9999, &stranger,
                                 CHIMERA_ACE_READ_DATA, 0);
    assert(g == 0);

    /* A caller whose SID set holds a different SID matches nothing. */
    mkcred_sids(&stranger_sids, TEST_OTHER_SID, NULL);
    stranger.sids = &stranger_sids;
    g             = chimera_acl_access_check(acl, 0, 9999, 9999, &stranger,
                                             CHIMERA_ACE_READ_DATA, 0);
    assert(g == 0);

    /* A group SID ACE matches a caller carrying that SID among its groups. */
    acl->aces[0].who.type = CHIMERA_PRINCIPAL_SID;
    memset(&acl->aces[0].who.sid, 0, sizeof(acl->aces[0].who.sid));
    assert(chimera_sid_from_str(&acl->aces[0].who.sid, TEST_GROUP_SID) == 0);

    mkcred_sids(&grp_sids, TEST_OTHER_SID, TEST_GROUP_SID);
    grpmbr.sids = &grp_sids;
    g           = chimera_acl_access_check(acl, 0, 9999, 9999, &grpmbr,
                                           CHIMERA_ACE_READ_DATA, 0);
    assert(g == CHIMERA_ACE_READ_DATA);

    TEST_PASS("opaque SID ACEs enforce against the caller's SID set");
} /* test_opaque_sid_ace_enforces */

/*
 * A DENY ACE naming a bare SID must deny, and an absent SID on either side
 * must never match -- an all-zero chimera_sid is "no SID known", not a
 * wildcard, so two identities that both lack a SID are not the same identity.
 */
static void
test_opaque_sid_ace_denies(void)
{
    ACL_BUF(acl, 4);
    struct chimera_vfs_cred      caller = mkcred(1500, 1500);
    struct chimera_vfs_cred_sids caller_sids;
    uint32_t                     g;

    memset(acl, 0, sizeof(struct chimera_acl) + 2 * sizeof(struct chimera_ace));
    acl->num_aces            = 2;
    acl->aces[0].type        = CHIMERA_ACE_DENIED;
    acl->aces[0].access_mask = CHIMERA_ACE_WRITE_DATA;
    acl->aces[0].who.type    = CHIMERA_PRINCIPAL_SID;
    assert(chimera_sid_from_str(&acl->aces[0].who.sid, TEST_USER_SID) == 0);

    acl->aces[1].type        = CHIMERA_ACE_ALLOWED;
    acl->aces[1].access_mask = CHIMERA_ACE_READ_DATA | CHIMERA_ACE_WRITE_DATA;
    acl->aces[1].who.type    = CHIMERA_PRINCIPAL_SPECIAL;
    acl->aces[1].who.special = CHIMERA_WHO_EVERYONE;

    mkcred_sids(&caller_sids, TEST_USER_SID, NULL);
    caller.sids = &caller_sids;

    /* DENY comes first and removes WRITE; the EVERYONE@ ALLOW still gives READ. */
    g = chimera_acl_access_check(acl, 0, 9999, 9999, &caller,
                                 CHIMERA_ACE_READ_DATA | CHIMERA_ACE_WRITE_DATA, 0);
    assert(g == CHIMERA_ACE_READ_DATA);

    /* An ACE whose SID is absent matches nobody, even a caller with no SIDs. */
    memset(&acl->aces[0].who.sid, 0, sizeof(acl->aces[0].who.sid));
    memset(&caller_sids, 0, sizeof(caller_sids));
    g = chimera_acl_access_check(acl, 0, 9999, 9999, &caller,
                                 CHIMERA_ACE_WRITE_DATA, 0);
    assert(g == CHIMERA_ACE_WRITE_DATA);

    TEST_PASS("opaque SID DENY applies; an absent SID is never a wildcard");
} /* test_opaque_sid_ace_denies */
```

Register both in `main()` alongside the existing calls:

```c
    test_opaque_sid_ace_enforces();
    test_opaque_sid_ace_denies();
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
sudo ninja -C build/Debug vfs_acl_test
```

Expected: FAIL. The compiler rejects `named.sids` -- `struct chimera_vfs_cred` has no member named `sids`.

- [ ] **Step 3: Add the SID set type and the cred field**

In `src/vfs/sdk/vfs_cred.h`, add the include near the top with the other includes:

```c
#include "vfs_sid.h"
```

Then, immediately above `struct chimera_vfs_cred`:

```c
/*
 * The native SIDs that describe a caller: its own user SID, plus one per group
 * it belongs to (its primary gid and every supplementary gid).  Resolved once
 * per credential by the identity layer and attached to the credential by
 * pointer, so an ACE carrying a bare Windows SID can be matched against the
 * caller with a byte comparison instead of mapping the ACE back to a uid.
 *
 * A slot whose SID is absent (chimera_sid_present() is false) is a group or
 * user the identity layer could not name; it is skipped when matching, never
 * treated as a wildcard.  `ngroups` counts the populated entries of groups[],
 * which holds the primary gid plus CHIMERA_VFS_CRED_MAX_GIDS supplementary
 * ones.
 */
struct chimera_vfs_cred_sids {
    uint32_t           ngroups;
    struct chimera_sid user;
    struct chimera_sid groups[CHIMERA_VFS_CRED_MAX_GIDS + 1];
};
```

Add the field at the end of `struct chimera_vfs_cred`, after `flags`:

```c
    /* Native SIDs describing this caller, or NULL when none were resolved.
     * Owned by the layer that built the credential (the SMB session, or the
     * VFS thread's credential-SID cache) and must outlive every request
     * carrying a copy of this credential.  Like `origin` and `flags`, NOT part
     * of the credential identity hash: it is a derived view of uid/gid/gids,
     * so two credentials that hash equal describe the same SID set. */
    const struct chimera_vfs_cred_sids *sids;
```

- [ ] **Step 4: Clear the new field in every initialiser**

`sids` is a pointer that access evaluation dereferences, so an uninitialised one is a crash. Find every initialiser and every place a credential is built without one:

```bash
grep -rn "chimera_vfs_cred_init" src/ --include=*.c --include=*.h
grep -rn "struct chimera_vfs_cred.*;" src/ --include=*.c | grep -v "const\|\*"
```

In `src/vfs/sdk/vfs_cred.h`, add `cred->sids = NULL;` to the body of `chimera_vfs_cred_init_anonymous`. In `src/vfs/vfs_cred.c`, add the same line to `chimera_vfs_cred_init_unix` and `chimera_vfs_cred_init_attr`, and to the stack credential built around `src/vfs/vfs_cred.c:78`.

Any credential built by `memset(&cred, 0, sizeof(cred))` is already correct. For any stack credential the grep turns up that is neither memset nor passed to an initialiser, add an explicit `cred.sids = NULL;`.

- [ ] **Step 5: Add the matcher and wire the ace_applies() SID arm**

In `src/vfs/vfs_acl.c`, add immediately after `cred_in_group()`:

```c
/*
 * Does `sid` name this caller?  True when it is the caller's own user SID or
 * one of its group SIDs.  An absent SID on either side never matches: an
 * all-zero chimera_sid means "no SID is known", not "any SID", so two
 * identities that both lack one are not thereby the same identity.
 */
static int
cred_matches_sid(
    const struct chimera_vfs_cred *cred,
    const struct chimera_sid      *sid)
{
    const struct chimera_vfs_cred_sids *sids = cred->sids;
    uint32_t                            i;

    if (!sids || !chimera_sid_present(sid)) {
        return 0;
    }

    if (chimera_sid_equal(&sids->user, sid)) {
        return 1;
    }

    for (i = 0; i < sids->ngroups; i++) {
        if (chimera_sid_equal(&sids->groups[i], sid)) {
            return 1;
        }
    }

    return 0;
} /* cred_matches_sid */
```

Replace the `CHIMERA_PRINCIPAL_SID` arm of `ace_applies()` (`src/vfs/vfs_acl.c:118-122`):

```c
        case CHIMERA_PRINCIPAL_SID:
            /* A native Windows SID with no unix identity on the ACE.  It still
             * describes a caller when the identity layer resolved that caller
             * to the same SID -- which is how a descriptor written by another
             * SMB stack, carrying only bare domain SIDs, enforces here.  A SID
             * that names no caller we know matches nobody, which is the
             * correct fail-closed default. */
            return cred_matches_sid(cred, &who->sid);
```

Note that `CHIMERA_PRINCIPAL_USER` and `CHIMERA_PRINCIPAL_GROUP` are deliberately left alone: they carry a numeric id, which is authoritative and cheaper than a SID comparison.

- [ ] **Step 6: Bump the SDK version**

`struct chimera_vfs_cred` is an SDK type whose layout just changed, so an out-of-tree module built against version 2 must be rejected at dlopen. In `src/vfs/sdk/vfs_module.h:31`:

```c
#define CHIMERA_VFS_SDK_VERSION             3
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
sudo ninja -C build/Debug vfs_acl_test && sudo./build/Debug/src/vfs/tests/vfs_acl_test
```

Expected: PASS for both new cases and every pre-existing case in the file.

- [ ] **Step 8: Verify the whole tree still builds and the ACL suite is green**

```bash
sudo ninja -C build/Debug
cd build/Debug && sudo ctest -R "chimera/vfs/(acl|sid|idmap)" --output-on-failure
```

Expected: build clean, all matched tests pass.

- [ ] **Step 9: Format and commit**

```bash
for f in src/vfs/sdk/vfs_cred.h src/vfs/sdk/vfs_module.h src/vfs/vfs_cred.c \
         src/vfs/vfs_acl.c src/vfs/tests/vfs_acl_test.c; do
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
done
git add src/vfs/sdk/vfs_cred.h src/vfs/sdk/vfs_module.h src/vfs/vfs_cred.c \
        src/vfs/vfs_acl.c src/vfs/tests/vfs_acl_test.c
git commit -m "vfs: match native SID ACEs against the caller's SID set

An ACE carrying only a native Windows SID could never describe a Unix
caller, so a descriptor written by another SMB stack -- bare domain SIDs
and no POSIX identity -- enforced nothing, and a non-empty ACL suppresses
the mode fallback.  Give the credential the set of SIDs that name it and
compare the ACE against that, which needs no change to the stored
descriptor and costs nothing for a SID that names no caller we know.

Signed-off-by: Alain Renaud <alain.renaud@quantum.com>"
```

---

### Task 2: Negative caching and in-flight de-duplication in the identity resolver

Without this, a credential whose uid or gids have no SID re-dispatches a blocking winbind lookup on every resolve, and N concurrent callers for the same key queue N jobs. The resolver caches only successes today (`src/vfs/vfs_identity.c:249-270`) and coalesces nothing.

**Files:**
- Modify: `src/vfs/vfs_identity.c`
- Test: `src/vfs/tests/vfs_identity_test.c`

**Interfaces:**
- Consumes: nothing from Task 1; this task is independent and may be done in parallel.
- Produces: no new public symbols. `chimera_vfs_identity_resolve()` keeps its exact signature and semantics; it simply completes with NULL from a cached negative, and attaches to an in-flight job rather than queueing a duplicate. Task 3 relies on both behaviours but calls only the existing API.

- [ ] **Step 1: Write the failing test**

Add to `src/vfs/tests/vfs_identity_test.c`. It uses a counting handler so the test can assert how many times the miss handler actually ran:

```c
/*
 * Counts how often it was asked, and never resolves anything.  Lets the test
 * assert that a repeated unresolvable key does NOT re-enter the handler (the
 * negative cache answered), and that concurrent resolves of one key enter it
 * exactly once (the in-flight join answered the rest).
 */
struct counting_handler_state {
    int calls;
};

static int
counting_handler(
    enum chimera_vfs_identity_key       key,
    uint32_t                            id,
    const char                         *name,
    struct chimera_vfs_identity_result *out,
    void                               *private_data)
{
    struct counting_handler_state *st = private_data;

    (void) key;
    (void) id;
    (void) name;
    (void) out;

    __sync_fetch_and_add(&st->calls, 1);
    return -1;
} /* counting_handler */

/*
 * An unresolvable key is cached as a negative: the second resolve completes
 * with NULL without re-running the miss handlers.
 */
static void
test_negative_cache(
    struct chimera_vfs        *vfs,
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct counting_handler_state st = {.calls = 0 };
    struct probe                  p1, p2;

    chimera_vfs_identity_register_handler(vfs, counting_handler, &st);

    memset(&p1, 0, sizeof(p1));
    chimera_vfs_identity_resolve(thread, CHIMERA_VFS_IDENTITY_BY_SID, 0,
                                 "S-1-5-21-999-999-999-4242", resolve_cb, &p1);
    while (!p1.done) {
        evpl_continue(evpl);
    }
    assert(!p1.found);
    assert(st.calls == 1);

    /* Second resolve of the same key: answered from the negative cache. */
    memset(&p2, 0, sizeof(p2));
    chimera_vfs_identity_resolve(thread, CHIMERA_VFS_IDENTITY_BY_SID, 0,
                                 "S-1-5-21-999-999-999-4242", resolve_cb, &p2);
    assert(p2.done);   /* fired inline, no park */
    assert(!p2.found);
    assert(st.calls == 1);

    TEST_PASS("an unresolvable key is negatively cached and answered inline");
} /* test_negative_cache */

/*
 * Two resolves of the same uncached key issued back to back run the miss
 * handlers once; the second joins the in-flight job and both callbacks fire.
 */
static void
test_inflight_dedup(
    struct chimera_vfs        *vfs,
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct counting_handler_state st = {.calls = 0 };
    struct probe                  p1, p2;

    chimera_vfs_identity_register_handler(vfs, counting_handler, &st);

    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));

    chimera_vfs_identity_resolve(thread, CHIMERA_VFS_IDENTITY_BY_SID, 0,
                                 "S-1-5-21-999-999-999-4243", resolve_cb, &p1);
    chimera_vfs_identity_resolve(thread, CHIMERA_VFS_IDENTITY_BY_SID, 0,
                                 "S-1-5-21-999-999-999-4243", resolve_cb, &p2);

    while (!p1.done || !p2.done) {
        evpl_continue(evpl);
    }

    assert(!p1.found);
    assert(!p2.found);
    assert(st.calls == 1);

    TEST_PASS("concurrent resolves of one key run the miss handlers once");
} /* test_inflight_dedup */
```

Call both from `main()` after the existing cases, passing the `vfs`, `thread` and `evpl` the file already sets up.

- [ ] **Step 2: Run the test to verify it fails**

```bash
sudo ninja -C build/Debug vfs_identity_test && sudo./build/Debug/src/vfs/tests/vfs_identity_test
```

Expected: FAIL. `test_negative_cache` aborts on `assert(p2.done)` (the second resolve parks instead of answering inline) or on `assert(st.calls == 1)`.

- [ ] **Step 3: Add the negative-cache and in-flight structures**

In `src/vfs/vfs_identity.c`, add after the `chimera_vfs_identity_request` definition:

```c
/* How long an unresolvable key stays remembered, and how many buckets the
 * negative table has.  Short enough that a newly-created account resolves
 * without a restart, long enough that a descriptor full of dead SIDs does not
 * re-enter winbind on every access. */
#define CHIMERA_VFS_IDENTITY_NEGATIVE_TTL     60
#define CHIMERA_VFS_IDENTITY_NEGATIVE_BUCKETS 256

struct chimera_vfs_identity_negative {
    struct chimera_vfs_identity_negative *next;
    enum chimera_vfs_identity_key         key;
    uint32_t                              id;
    time_t                                expiration;
    char                                  name[CHIMERA_VFS_SID_MAX_LEN > 256 ?
                                               CHIMERA_VFS_SID_MAX_LEN : 256];
};
```

Extend `struct chimera_vfs_identity` with:

```c
    /* Jobs handed to a worker and not yet completed, so a second resolve of
     * the same key joins the one in flight instead of queueing a duplicate.
     * Guarded by `lock`, like `queue`. */
    struct chimera_vfs_identity_request  *inflight;
    /* Keys the handlers could not resolve, remembered with a TTL. */
    struct chimera_vfs_identity_negative *negative[
        CHIMERA_VFS_IDENTITY_NEGATIVE_BUCKETS];
```

Add a `waiters` list head to `struct chimera_vfs_identity_request`:

```c
    /* Later resolves of the same key that joined this job; each is completed
     * with a copy of this job's result. */
    struct chimera_vfs_identity_request *waiters;
```

Add `#include <time.h>` to the includes if it is not already pulled in.

- [ ] **Step 4: Add the key-matching and negative-table helpers**

Add above `chimera_vfs_identity_resolve()`:

```c
/*
 * Two identity requests name the same key.  The numeric keys compare on `id`
 * and the string keys on `name`, because only one of the two is meaningful per
 * key and comparing the other would split identical lookups.
 */
static int
chimera_vfs_identity_key_eq(
    enum chimera_vfs_identity_key key,
    uint32_t                      id,
    const char                   *name,
    enum chimera_vfs_identity_key okey,
    uint32_t                      oid,
    const char                   *oname)
{
    if (key != okey) {
        return 0;
    }

    if (key == CHIMERA_VFS_IDENTITY_BY_UID ||
        key == CHIMERA_VFS_IDENTITY_BY_GID) {
        return id == oid;
    }

    return name && oname && strcmp(name, oname) == 0;
} /* chimera_vfs_identity_key_eq */

static unsigned int
chimera_vfs_identity_negative_hash(
    enum chimera_vfs_identity_key key,
    uint32_t                      id,
    const char                   *name)
{
    unsigned int h = (unsigned int) key * 2654435761u;

    if (key == CHIMERA_VFS_IDENTITY_BY_UID ||
        key == CHIMERA_VFS_IDENTITY_BY_GID) {
        h ^= id * 2654435761u;
    } else if (name) {
        for (const char *p = name; *p; p++) {
            h = (h * 31u) + (unsigned char) *p;
        }
    }

    return h % CHIMERA_VFS_IDENTITY_NEGATIVE_BUCKETS;
} /* chimera_vfs_identity_negative_hash */

/* Caller holds identity->lock.  Non-zero if this key is a live negative. */
static int
chimera_vfs_identity_negative_probe(
    struct chimera_vfs_identity  *identity,
    enum chimera_vfs_identity_key key,
    uint32_t                      id,
    const char                   *name)
{
    unsigned int                           b;
    struct chimera_vfs_identity_negative  *neg, **pp;
    struct timespec                        now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    b  = chimera_vfs_identity_negative_hash(key, id, name);
    pp = &identity->negative[b];

    while (*pp) {
        neg = *pp;

        if (neg->expiration <= now.tv_sec) {
            /* Expired: drop it as we walk, which keeps the table swept without
             * a separate timer. */
            *pp = neg->next;
            free(neg);
            continue;
        }

        if (chimera_vfs_identity_key_eq(key, id, name,
                                        neg->key, neg->id, neg->name)) {
            return 1;
        }

        pp = &neg->next;
    }

    return 0;
} /* chimera_vfs_identity_negative_probe */

/* Caller holds identity->lock. */
static void
chimera_vfs_identity_negative_add(
    struct chimera_vfs_identity  *identity,
    enum chimera_vfs_identity_key key,
    uint32_t                      id,
    const char                   *name)
{
    unsigned int                          b;
    struct chimera_vfs_identity_negative *neg;
    struct timespec                       now;

    if (chimera_vfs_identity_negative_probe(identity, key, id, name)) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);

    neg             = calloc(1, sizeof(*neg));
    neg->key        = key;
    neg->id         = id;
    neg->expiration = now.tv_sec + CHIMERA_VFS_IDENTITY_NEGATIVE_TTL;
    if (name) {
        strncpy(neg->name, name, sizeof(neg->name) - 1);
    }

    b                    = chimera_vfs_identity_negative_hash(key, id, name);
    neg->next            = identity->negative[b];
    identity->negative[b] = neg;
} /* chimera_vfs_identity_negative_add */
```

- [ ] **Step 5: Consult the negative cache and the in-flight list in resolve**

Replace the miss half of `chimera_vfs_identity_resolve()` (`src/vfs/vfs_identity.c:489-508`), keeping the cache-hit fast path above it untouched:

```c
    /* Miss: dispatch to a worker and park (the callback fires on `thread`'s
     * evpl loop once the worker has resolved and cached the identity). */
    req               = calloc(1, sizeof(*req));
    req->origin       = thread;
    req->key          = key;
    req->id           = id;
    req->callback     = callback;
    req->private_data = private_data;
    if (name) {
        strncpy(req->name, name, sizeof(req->name) - 1);
    }

    pthread_mutex_lock(&identity->lock);

    /* Remembered as unresolvable: answer now rather than re-entering a
     * blocking miss handler.  A descriptor full of SIDs from a decommissioned
     * domain would otherwise cost one winbind round trip per ACE per access. */
    if (chimera_vfs_identity_negative_probe(identity, key, id, req->name)) {
        pthread_mutex_unlock(&identity->lock);
        free(req);
        callback(NULL, private_data);
        return;
    }

    /* Already being resolved: join that job.  Its completion fans the one
     * result out to every waiter, on each waiter's own origin thread. */
    DL_FOREACH2(identity->inflight, inflight, inflight_next)
    {
        if (chimera_vfs_identity_key_eq(key, id, req->name,
                                        inflight->key, inflight->id,
                                        inflight->name)) {
            DL_APPEND(inflight->waiters, req);
            pthread_mutex_unlock(&identity->lock);
            return;
        }
    }

    DL_APPEND(identity->queue, req);
    DL_APPEND2(identity->inflight, req, inflight_prev, inflight_next);
    pthread_cond_signal(&identity->cond);
    pthread_mutex_unlock(&identity->lock);
```

This needs a second pair of list links on the request so a job can sit on `queue` and `inflight` at once, and the `waiters` list uses the original `prev`/`next`. Add to `struct chimera_vfs_identity_request`:

```c
    struct chimera_vfs_identity_request *inflight_prev;
    struct chimera_vfs_identity_request *inflight_next;
```

and declare `struct chimera_vfs_identity_request *inflight;` among the locals of `chimera_vfs_identity_resolve()`.

- [ ] **Step 6: Record negatives and fan out to waiters in the worker**

In `chimera_vfs_identity_worker()`, replace the block from `} else { req->found = 0; }` through the hand-back (`src/vfs/vfs_identity.c:265-279`):

```c
        } else {
            req->found = 0;
        }

        pthread_mutex_lock(&identity->lock);

        if (!req->found) {
            chimera_vfs_identity_negative_add(identity, req->key, req->id,
                                              req->name);
        }

        DL_DELETE2(identity->inflight, req, inflight_prev, inflight_next);
        waiters       = req->waiters;
        req->waiters  = NULL;

        pthread_mutex_unlock(&identity->lock);

        /* Fan the single result out to everyone who joined this job.  Each
         * waiter resumes on its own origin thread, which is why the result is
         * copied rather than shared. */
        while (waiters) {
            waiter = waiters;
            DL_DELETE(waiters, waiter);

            waiter->found  = req->found;
            waiter->result = req->result;

            pthread_mutex_lock(&waiter->origin->lock);
            DL_APPEND(waiter->origin->pending_identity, waiter);
            pthread_mutex_unlock(&waiter->origin->lock);

            evpl_ring_doorbell(&waiter->origin->doorbell);
        }

        /* Hand the completed job back to the originating evpl thread. */
        pthread_mutex_lock(&req->origin->lock);
        DL_APPEND(req->origin->pending_identity, req);
        pthread_mutex_unlock(&req->origin->lock);

        evpl_ring_doorbell(&req->origin->doorbell);
```

Declare `struct chimera_vfs_identity_request *waiters, *waiter;` among the worker's locals.

- [ ] **Step 7: Free the negative table at shutdown**

In `chimera_vfs_identity_destroy()`, alongside the existing queue drain, add:

```c
    for (int b = 0; b < CHIMERA_VFS_IDENTITY_NEGATIVE_BUCKETS; b++) {
        struct chimera_vfs_identity_negative *neg, *neg_next;

        neg = identity->negative[b];
        while (neg) {
            neg_next = neg->next;
            free(neg);
            neg = neg_next;
        }
        identity->negative[b] = NULL;
    }
```

Any request still on `queue` at shutdown is freed by the existing drain; free its `waiters` list there too, in the same loop that frees the job.

- [ ] **Step 8: Run the tests to verify they pass**

```bash
sudo ninja -C build/Debug vfs_identity_test && \
    sudo./build/Debug/src/vfs/tests/vfs_identity_test
```

Expected: PASS, including the pre-existing cases (the SID-bearing handler test in particular, which depends on handlers being re-run for a numeric key).

- [ ] **Step 9: Run under the debug build's sanitizers**

The debug build carries AddressSanitizer; the fan-out touches lists across threads, so confirm it cleanly.

```bash
cd build/Debug && sudo ctest -R "chimera/vfs/(identity|user_cache)" --output-on-failure
```

Expected: PASS with no ASan report.

- [ ] **Step 10: Format and commit**

```bash
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/vfs_identity.c
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/vfs_identity.c
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/tests/vfs_identity_test.c
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/tests/vfs_identity_test.c
git add src/vfs/vfs_identity.c src/vfs/tests/vfs_identity_test.c
git commit -m "vfs: remember unresolvable identities and coalesce in-flight lookups

The resolver cached only successes, so a key no handler can resolve
re-entered a blocking winbind lookup on every attempt, and concurrent
resolves of one key each queued their own job.  Remember a failure for a
minute and let a later resolve of a key already in flight join it.

Signed-off-by: Alain Renaud <alain.renaud@quantum.com>"
```

---

### Task 3: The credential SID resolver

Turns a credential into a `chimera_vfs_cred_sids`, warm-path inline and cold-path parked, behind a per-thread cache.

**Files:**
- Create: `src/vfs/vfs_cred_sids.h`
- Create: `src/vfs/vfs_cred_sids.c`
- Modify: `src/vfs/CMakeLists.txt`
- Create: `src/vfs/tests/vfs_cred_sids_test.c`
- Modify: `src/vfs/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `struct chimera_vfs_cred_sids` from Task 1; `chimera_vfs_identity_resolve()` with the negative-cache and de-duplication behaviour from Task 2; `chimera_vfs_cred_hash()` from `src/vfs/sdk/vfs_cred.h`; `chimera_sid_from_str()` from `src/vfs/sdk/vfs_sid.h`.
- Produces, for Tasks 4 and 5:
  - `void chimera_vfs_cred_resolve_sids(struct chimera_vfs_thread *thread, const struct chimera_vfs_cred *cred, chimera_vfs_cred_sids_callback callback, void *private_data)` -- async; the callback receives a `const struct chimera_vfs_cred_sids *` borrowed for the duration of the callback, or NULL if nothing resolved.
  - `const struct chimera_vfs_cred_sids *chimera_vfs_cred_sids_lookup(struct chimera_vfs_thread *thread, const struct chimera_vfs_cred *cred)` -- synchronous; returns a borrowed set if this thread has one cached, else NULL. Never blocks, never resolves.
  - `void chimera_vfs_cred_sids_warm(struct chimera_vfs_thread *thread, const struct chimera_vfs_cred *cred)` -- fire-and-forget resolve so a later `_lookup` hits.
  - `typedef void (*chimera_vfs_cred_sids_callback)(const struct chimera_vfs_cred_sids *sids, void *private_data);`

**Borrow contract, stated once here because both callers depend on it:** the pointer handed to the callback, and the one returned by `_lookup`, belong to the thread's cache. They are valid until the calling thread returns to its event loop. A caller that needs the set to outlive that (the SMB session in Task 4) must copy it.

- [ ] **Step 1: Write the header**

Create `src/vfs/vfs_cred_sids.h`:

```c
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
```

- [ ] **Step 2: Write the failing test**

Create `src/vfs/tests/vfs_cred_sids_test.c`. Model the evpl/vfs setup on `src/vfs/tests/vfs_identity_test.c` (same `chimera_vfs_create` / thread-init / `evpl_continue` shape); the assertions specific to this task are:

```c
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
        out->is_group  = 0;
        out->user.uid  = TEST_UID;
        out->user.gid  = TEST_GID;
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
test_lookup_misses_before_warm(
    struct chimera_vfs_thread *thread)
{
    struct chimera_vfs_cred cred;

    /* A credential this thread has never resolved: the synchronous probe must
     * say so rather than blocking or inventing an answer. */
    chimera_vfs_cred_init_unix(&cred, 4999, 4999, 0, NULL);
    assert(chimera_vfs_cred_sids_lookup(thread, &cred) == NULL);

    TEST_PASS("synchronous lookup misses on an unseen credential");
} /* test_lookup_misses_before_warm */
```

Give it a `main()` that creates the VFS and thread the way `vfs_identity_test.c` does, calls `test_lookup_misses_before_warm()` then `test_resolve_and_cache()`, and tears down.

- [ ] **Step 3: Register the new source and test with the build**

In `src/vfs/CMakeLists.txt`, add `vfs_cred_sids.c` to the `chimera_vfs` source list, next to `vfs_identity.c`.

In `src/vfs/tests/CMakeLists.txt`, after the `vfs_identity_test` block:

```cmake
add_executable(vfs_cred_sids_test vfs_cred_sids_test.c)
target_link_libraries(vfs_cred_sids_test chimera_vfs chimera_vfs_memfs evpl)
add_test(chimera/vfs/cred_sids_test vfs_cred_sids_test)
```

- [ ] **Step 4: Run the test to verify it fails**

```bash
sudo ninja -C build/Debug vfs_cred_sids_test
```

Expected: FAIL at link (or at compile on the missing `vfs_cred_sids.h`) -- `chimera_vfs_cred_resolve_sids` is undefined.

- [ ] **Step 5: Implement the resolver**

Create `src/vfs/vfs_cred_sids.c`:

```c
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
```

The cache lives on the thread. Add to `struct chimera_vfs_thread` in `src/vfs/vfs.h`, after `pending_identity`:

```c
    /* Native SIDs per credential seen on this thread (see vfs_cred_sids.h). */
    struct chimera_vfs_cred_sids_cache  *cred_sids;
```

and forward-declare `struct chimera_vfs_cred_sids_cache;` near the other forward declarations in that header.

Then the body:

```c
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
    struct chimera_vfs_cred_sids_entry *entry, *last;
    unsigned int                        b;
    int                                 n = 0;

    if (!thread->cred_sids) {
        thread->cred_sids = calloc(1, sizeof(*thread->cred_sids));
    }

    entry = chimera_vfs_cred_sids_find(thread, hash);
    if (entry) {
        return entry;
    }

    b    = hash % CHIMERA_VFS_CRED_SIDS_BUCKETS;
    last = NULL;

    for (entry = thread->cred_sids->buckets[b]; entry; entry = entry->next) {
        last = entry;
        n++;
    }

    /* Bucket full: reuse the tail, the least recently interned in it.  Safe
     * because a borrowed set never outlives its callback, and no resolve can
     * start while another's callback is running on this single-threaded loop. */
    if (n >= CHIMERA_VFS_CRED_SIDS_CHAIN && last) {
        memset(last, 0, sizeof(*last));
        last->hash = hash;
        return last;
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

    memset(&entry->sids, 0, sizeof(entry->sids));
    entry->valid = 0;

    /* groups[] is the primary gid followed by the supplementary ones, in the
     * order the credential carries them, so a slot index maps straight back to
     * the gid it came from. */
    entry->sids.ngroups = 1 + cred->ngids;
    if (entry->sids.ngroups > CHIMERA_VFS_CRED_MAX_GIDS + 1) {
        entry->sids.ngroups = CHIMERA_VFS_CRED_MAX_GIDS + 1;
    }

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
```

Note the `ctx->pending` guard: it is seeded to 1 and dropped last, so an all-warm resolve (every `chimera_vfs_identity_resolve` firing inline) completes synchronously inside `chimera_vfs_cred_resolve_sids` rather than at the first inline callback.

- [ ] **Step 6: Call the teardown from VFS thread destroy**

Find the VFS thread teardown and add the call:

```bash
grep -n "chimera_vfs_thread_destroy" src/vfs/vfs.c
```

Add `chimera_vfs_cred_sids_thread_destroy(thread);` next to the other per-thread frees, and `#include "vfs_cred_sids.h"` at the top of `src/vfs/vfs.c`.

- [ ] **Step 7: Run the test to verify it passes**

```bash
sudo ninja -C build/Debug vfs_cred_sids_test && \
    sudo./build/Debug/src/vfs/tests/vfs_cred_sids_test
```

Expected: PASS on both cases, with no ASan leak report at exit.

- [ ] **Step 8: Format and commit**

```bash
for f in src/vfs/vfs_cred_sids.c src/vfs/vfs_cred_sids.h src/vfs/vfs.h \
         src/vfs/vfs.c src/vfs/tests/vfs_cred_sids_test.c; do
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
done
git add src/vfs/vfs_cred_sids.c src/vfs/vfs_cred_sids.h src/vfs/vfs.h \
        src/vfs/vfs.c src/vfs/CMakeLists.txt \
        src/vfs/tests/vfs_cred_sids_test.c src/vfs/tests/CMakeLists.txt
git commit -m "vfs: resolve a credential to its native SID set

Maps a credential to the SIDs that describe it -- its user SID and one
per group -- behind a per-thread cache, so ACL evaluation can match an
ACE carrying a bare domain SID against the caller.  A warm credential
resolves inline with no allocation; a cold one parks on the identity
resolver and resumes on its own thread.

Signed-off-by: Alain Renaud <alain.renaud@quantum.com>"
```

---

### Task 4: Populate the SMB session credential

SMB builds one credential per session, and every SMB operation borrows it -- including the access-based-enumeration check in the readdir entry callback, which cannot park. Resolving at session setup is what makes that path work with no probing at all.

**Files:**
- Modify: `src/server/smb/smb_session.h` (the session struct)
- Modify: `src/server/smb/smb_proc_session_setup.c:593-610`

**Interfaces:**
- Consumes: `chimera_vfs_cred_resolve_sids()` and the borrow contract from Task 3; the `sids` field from Task 1.
- Produces: nothing new. `session->cred.sids` points at `session->cred_sids`, valid for the life of the session.

- [ ] **Step 1: Write the failing test**

There is no SMB session unit-test harness, and standing one up is out of proportion here; this task's behaviour is covered end to end by Task 6 over the VFS, and by the manual SMB check in Task 7. The failing-test step for this task is therefore the Task 6 test, which must be written first if the tasks are reordered. Proceed to step 2.

- [ ] **Step 2: Add the session-owned SID set**

In `src/server/smb/smb_session.h`, add to the session struct next to `cred`:

```c
    /* Native SIDs describing this session's caller, pointed at by cred.sids.
     * Owned here so it lives exactly as long as the credential does; the
     * resolver's own copy is only borrowed for its callback. */
    struct chimera_vfs_cred_sids      cred_sids;
```

- [ ] **Step 3: Resolve at session setup**

`chimera_vfs_cred_init_attr(&session->cred, uid, gid, ngids, gids)` at `src/server/smb/smb_proc_session_setup.c:603` is the point the credential becomes final. Add a completion that copies the resolved set into the session, and issue the resolve immediately after the init.

Add above the function containing line 603:

```c
/*
 * Session setup has settled the caller's unix identity; take its native SIDs
 * too, so an ACE carrying only a domain SID can be matched against this
 * session.  The set is copied into the session because the resolver only lends
 * it for the duration of this callback, and the session credential outlives
 * every request that borrows it.
 */
static void
chimera_smb_session_sids_cb(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data)
{
    struct chimera_smb_session *session = private_data;

    if (sids) {
        session->cred_sids = *sids;
        session->cred.sids = &session->cred_sids;
    } else {
        /* Nothing about this caller is nameable as a SID.  Leave cred.sids
         * NULL: a SID-bearing ACE then matches nobody, which is the correct
         * fail-closed default. */
        session->cred.sids = NULL;
    }
} /* chimera_smb_session_sids_cb */
```

Immediately after the `chimera_vfs_cred_init_attr` call at line 603:

```c
            chimera_vfs_cred_resolve_sids(
                request->compound->thread->shared->vfs_thread,
                &session->cred,
                chimera_smb_session_sids_cb, session);
```

Use whatever expression in scope yields this thread's `struct chimera_vfs_thread *` -- check the surrounding function; elsewhere in the SMB server it is reached through the compound's thread. Confirm with:

```bash
grep -n "vfs_thread" src/server/smb/smb_proc_session_setup.c | head
```

Add `#include "vfs/vfs_cred_sids.h"` to the file's includes, and to `smb_session.h` add `#include "vfs/sdk/vfs_cred.h"` if it is not already there.

**On ordering:** the callback may fire inline (warm) or later (cold). Either is correct here -- the session credential starts with `sids == NULL`, and a request that arrives before the resolve completes is simply evaluated without SID matching, exactly as today. Do not make session setup wait on it.

- [ ] **Step 4: Verify it builds and the SMB suite is unaffected**

```bash
sudo ninja -C build/Debug
cd build/Debug && sudo ctest -R smb --output-on-failure
```

Expected: build clean, the SMB tests that run in the quick tier all pass.

- [ ] **Step 5: Format and commit**

```bash
for f in src/server/smb/smb_session.h src/server/smb/smb_proc_session_setup.c; do
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
done
git add src/server/smb/smb_session.h src/server/smb/smb_proc_session_setup.c
git commit -m "smb: resolve the session credential's native SIDs at setup

Every SMB operation borrows the session credential, so resolving its SID
set once at session setup makes SID-bearing ACEs enforce on all of them,
including the access-based-enumeration check in the readdir entry
callback, which cannot park.

Signed-off-by: Alain Renaud <alain.renaud@quantum.com>"
```

---

### Task 5: Populate the NFS request credential

`chimera_nfs_map_cred_req()` (`src/server/nfs/nfs_common.h:683-689`) is the single funnel every NFS request's credential passes through. It is synchronous, so it takes a warm set and kicks a background resolve on a miss.

**Files:**
- Modify: `src/server/nfs/nfs_common.h:683-689`
- Test: `src/vfs/tests/vfs_cred_sids_test.c` (extend)

**Interfaces:**
- Consumes: `chimera_vfs_cred_sids_lookup()` and `chimera_vfs_cred_sids_warm()` from Task 3.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

Add to `src/vfs/tests/vfs_cred_sids_test.c`. This pins the documented warm-then-enforce behaviour that the NFS path depends on:

```c
/*
 * The pattern the NFS per-request credential funnel uses: a synchronous probe
 * that misses, a background warm, and a hit on the next request.  The first
 * request proceeds with no SID set, which is today's behaviour and fails
 * closed; every request after it is enforced.
 */
static void
test_warm_then_lookup(
    struct chimera_vfs_thread *thread,
    struct evpl               *evpl)
{
    struct chimera_vfs_cred cred;

    chimera_vfs_cred_init_unix(&cred, TEST_UID, TEST_GID, 0, NULL);

    /* A fresh credential hash (no supplementary gids this time). */
    assert(chimera_vfs_cred_sids_lookup(thread, &cred) == NULL);

    chimera_vfs_cred_sids_warm(thread, &cred);

    /* Let any parked lookups complete. */
    for (int i = 0; i < 64 &&
         chimera_vfs_cred_sids_lookup(thread, &cred) == NULL; i++) {
        evpl_continue(evpl);
    }

    assert(chimera_vfs_cred_sids_lookup(thread, &cred) != NULL);
    assert(sid_str_is(&chimera_vfs_cred_sids_lookup(thread, &cred)->user,
                      TEST_UID_SID));

    TEST_PASS("warm-then-lookup enforces from the second request on");
} /* test_warm_then_lookup */
```

Call it from `main()` after `test_resolve_and_cache()`.

- [ ] **Step 2: Run the test to verify it fails**

```bash
sudo ninja -C build/Debug vfs_cred_sids_test && \
    sudo./build/Debug/src/vfs/tests/vfs_cred_sids_test
```

Expected: this case passes already if Task 3 is complete -- it exercises only Task 3's API. That is intentional: it is the contract Task 5 leans on, and it must be green before the NFS change is made. If it fails, fix Task 3 before continuing.

- [ ] **Step 3: Wire the NFS credential funnel**

Replace `chimera_nfs_map_cred_req()` in `src/server/nfs/nfs_common.h`:

```c
static inline void
chimera_nfs_map_cred_req(
    struct nfs_request          *req,
    const struct evpl_rpc2_cred *rpc_cred)
{
    chimera_nfs_map_cred(&req->cred, rpc_cred);

    /*
     * Attach the caller's native SIDs so an ACE carrying only a domain SID can
     * be matched against it (see cred_matches_sid in vfs_acl.c).  This runs on
     * the synchronous RPC path, so it takes only what the thread already has
     * and starts a resolve on a miss rather than parking: an unseen caller's
     * first request is evaluated with no SID set -- today's behaviour, and
     * fail-closed -- and every request after it is enforced.
     */
    req->cred.sids = chimera_vfs_cred_sids_lookup(req->thread->vfs_thread,
                                                  &req->cred);
    if (!req->cred.sids) {
        chimera_vfs_cred_sids_warm(req->thread->vfs_thread, &req->cred);
    }

    req->orig_cred = req->cred;
    req->sec_bit   = chimera_nfs_sec_bit(rpc_cred);
} /* chimera_nfs_map_cred_req */
```

Add `#include "vfs/vfs_cred_sids.h"` to `src/server/nfs/nfs_common.h`.

Squashing re-initialises the credential (`chimera_vfs_cred_init_anonymous` clears `sids` to NULL, per Task 1), which is correct: a squashed caller is the export's anonymous identity, not the original principal, and must not keep the original's SIDs.

- [ ] **Step 4: Check every path that rebuilds req->cred from orig_cred**

`req->cred = req->orig_cred` appears at `nfs4_proc_putfh.c:141`, `nfs4_proc_putrootfh.c:127`, `nfs4_proc_restorefh.c:29`, and `nfs_common.h:766` and `:783`. These copy the whole struct, so `sids` travels with it and needs no change. Confirm no path builds a credential field-by-field:

```bash
grep -rn "cred\.\(uid\|gid\|flavor\) *=" src/server/nfs/ | head -20
```

Any site that assigns fields individually rather than copying the struct must also set `sids`.

- [ ] **Step 5: Verify build and NFS tests**

```bash
sudo ninja -C build/Debug
cd build/Debug && sudo ctest -R "nfs|linux" --output-on-failure
```

Expected: build clean, tests pass.

- [ ] **Step 6: Format and commit**

```bash
for f in src/server/nfs/nfs_common.h src/vfs/tests/vfs_cred_sids_test.c; do
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
done
git add src/server/nfs/nfs_common.h src/vfs/tests/vfs_cred_sids_test.c
git commit -m "nfs: attach the caller's native SIDs to the request credential

The per-request credential funnel takes the SID set the thread already
resolved and starts a resolve on a miss.  An unseen caller's first
request is evaluated without it -- unchanged, fail-closed -- and every
request after it enforces SID-bearing ACEs.

Signed-off-by: Alain Renaud <alain.renaud@quantum.com>"
```

---

### Task 6: End-to-end enforcement over a real backend

The ticket's acceptance criteria call for unit coverage of three cases in `src/vfs/tests/`: an all-opaque DACL granting after resolution, an unresolvable SID denying, and the mixed case. This does it through the real VFS gate on memfs, so it exercises the actual access path rather than the pure ACL evaluator.

**Files:**
- Create: `src/vfs/tests/vfs_acl_sid_enforce_test.c`
- Modify: `src/vfs/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: everything from Tasks 1, 2 and 3. Uses the same memfs mount/lookup/open scaffolding as `src/vfs/tests/vfs_enforce_test.c` and the same fake-handler pattern as `src/vfs/tests/vfs_identity_test.c`.

- [ ] **Step 1: Write the test**

Create `src/vfs/tests/vfs_acl_sid_enforce_test.c`. Copy the harness (mount, lookup, create, setattr, open, read callbacks and `wait_done`) from `src/vfs/tests/vfs_enforce_test.c` verbatim -- it is the established shape for driving memfs from a test -- and add these cases on top:

```c
/*
 * A file whose DACL names only native domain SIDs.  Over SMB this is what a
 * descriptor migrated from another server looks like: bare SIDs, no POSIX
 * identity anywhere in the ACL, and a mode that grants nothing.
 */
#define ENF_OWNER_UID  7000
#define ENF_OWNER_GID  7000
#define ENF_USER_UID   7001
#define ENF_USER_GID   7001
#define ENF_GROUP_GID  7002

#define ENF_USER_SID   "S-1-5-21-77-88-99-1101"
#define ENF_GROUP_SID  "S-1-5-21-77-88-99-1102"
#define ENF_DEAD_SID   "S-1-5-21-77-88-99-9999"

static int
enf_identity_handler(
    enum chimera_vfs_identity_key       key,
    uint32_t                            id,
    const char                         *name,
    struct chimera_vfs_identity_result *out,
    void                               *private_data)
{
    (void) name;
    (void) private_data;

    if (key == CHIMERA_VFS_IDENTITY_BY_UID && id == ENF_USER_UID) {
        out->is_group = 0;
        out->user.uid = ENF_USER_UID;
        out->user.gid = ENF_USER_GID;
        snprintf(out->user.username, sizeof(out->user.username), "enfuser");
        out->user.username_len = (int) strlen(out->user.username);
        snprintf(out->user.sid, sizeof(out->user.sid), ENF_USER_SID);
        return 0;
    }

    if (key == CHIMERA_VFS_IDENTITY_BY_GID && id == ENF_GROUP_GID) {
        out->is_group  = 1;
        out->group.gid = ENF_GROUP_GID;
        snprintf(out->group.groupname, sizeof(out->group.groupname), "enfgrp");
        out->group.groupname_len = (int) strlen(out->group.groupname);
        snprintf(out->group.sid, sizeof(out->group.sid), ENF_GROUP_SID);
        return 0;
    }

    /* Every other id, including ENF_DEAD_SID's, is unresolvable. */
    return -1;
} /* enf_identity_handler */

/* Build a DACL of `n` ALLOW ACEs, each naming a bare SID string. */
static void
enf_build_sid_acl(
    struct chimera_acl *acl,
    const char        **sids,
    unsigned            n,
    uint32_t            mask)
{
    memset(acl, 0, chimera_acl_size(n));
    acl->num_aces = (uint16_t) n;

    for (unsigned i = 0; i < n; i++) {
        acl->aces[i].type        = CHIMERA_ACE_ALLOWED;
        acl->aces[i].access_mask = mask;
        acl->aces[i].who.type    = CHIMERA_PRINCIPAL_SID;
        assert(chimera_sid_from_str(&acl->aces[i].who.sid, sids[i]) == 0);
    }
} /* enf_build_sid_acl */
```

Then three cases, each: create a file owned by `ENF_OWNER_UID` with mode 0600, set the DACL with `chimera_vfs_setattr`, resolve the test credential's SIDs, and attempt a read through `chimera_vfs_read` (which goes through the gate, hence the real access check).

```c
/*
 * All-opaque DACL: a single ALLOW ACE naming the caller's user SID.  Before
 * this work it granted nobody and the non-empty ACL suppressed the mode
 * fallback, so the file could be stat'ed and not opened.
 */
static void
test_all_opaque_dacl_grants(struct test_ctx *ctx)
{
    const char *sids[1] = { ENF_USER_SID };
    ACL_BUF(acl, 1);

    enf_build_sid_acl(acl, sids, 1,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_grant", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 0, NULL);

    assert(enf_try_read(ctx, "opaque_grant") == CHIMERA_VFS_OK);

    TEST_PASS("an all-SID DACL grants the caller whose SID it names");
} /* test_all_opaque_dacl_grants */

/*
 * A SID nothing can resolve still matches nobody -- the fail-closed default
 * the ticket keeps deliberately.
 */
static void
test_unresolvable_sid_denies(struct test_ctx *ctx)
{
    const char *sids[1] = { ENF_DEAD_SID };
    ACL_BUF(acl, 1);

    enf_build_sid_acl(acl, sids, 1,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_deny", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 0, NULL);

    assert(enf_try_read(ctx, "opaque_deny") == CHIMERA_VFS_EACCES);

    TEST_PASS("an unresolvable SID matches no caller");
} /* test_unresolvable_sid_denies */

/*
 * Mixed: one dead SID, one live group SID.  The dead ACE must not poison the
 * walk, and the caller must be granted through its group membership.
 */
static void
test_mixed_dacl(struct test_ctx *ctx)
{
    const char *sids[2] = { ENF_DEAD_SID, ENF_GROUP_SID };
    uint32_t    gids[1] = { ENF_GROUP_GID };
    ACL_BUF(acl, 2);

    enf_build_sid_acl(acl, sids, 2,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_mixed", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 1, gids);

    assert(enf_try_read(ctx, "opaque_mixed") == CHIMERA_VFS_OK);

    TEST_PASS("a live group SID grants through a DACL that also holds a dead one");
} /* test_mixed_dacl */

/*
 * The stored descriptor must come back byte-identical: evaluation reads the
 * ACL and never writes it.
 */
static void
test_descriptor_unchanged(struct test_ctx *ctx)
{
    const char *sids[1] = { ENF_USER_SID };
    ACL_BUF(acl, 1);
    ACL_BUF(after, 1);

    enf_build_sid_acl(acl, sids, 1,
                      CHIMERA_ACE_READ_DATA | CHIMERA_ACE_READ_ATTRIBUTES);

    enf_create_file_with_acl(ctx, "opaque_stable", acl);
    enf_resolve_cred(ctx, ENF_USER_UID, ENF_USER_GID, 0, NULL);

    assert(enf_try_read(ctx, "opaque_stable") == CHIMERA_VFS_OK);

    enf_get_acl(ctx, "opaque_stable", after);
    assert(memcmp(acl, after, chimera_acl_size(1)) == 0);

    TEST_PASS("the stored descriptor is byte-identical after an access check");
} /* test_descriptor_unchanged */
```

The file needs its own `ACL_BUF` (the one in `vfs_acl_test.c` is file-local) and these four helpers. Extend the copied `struct test_ctx` with `struct chimera_vfs_cred cred;`, `struct chimera_vfs_cred_sids cred_sids;` and `struct chimera_acl *acl_out;`.

```c
#define ACL_BUF(name, n)                                              \
        uint8_t name ## _storage[sizeof(struct chimera_acl) +         \
                                 (n) * sizeof(struct chimera_ace)];   \
        struct chimera_acl *name = (struct chimera_acl *) name ## _storage

/*
 * Create `name` owned by ENF_OWNER_UID with mode 0600 -- a mode that grants the
 * test caller nothing, so any access it gets must come from the DACL -- then
 * set `acl` on it.
 *
 * chimera_vfs_setattr is issued with a freshly built attrs struct because a
 * backend rewrites the caller's va_set_mask in place, so an attrs struct must
 * never be reused across two setattr calls.
 */
static void
enf_create_file_with_acl(
    struct test_ctx    *ctx,
    const char         *name,
    struct chimera_acl *acl)
{
    struct chimera_vfs_attrs set_attr;

    memset(&set_attr, 0, sizeof(set_attr));
    set_attr.va_req_mask = CHIMERA_VFS_ATTR_MODE | CHIMERA_VFS_ATTR_UID |
        CHIMERA_VFS_ATTR_GID;
    set_attr.va_set_mask = set_attr.va_req_mask;
    set_attr.va_mode     = S_IFREG | 0600;
    set_attr.va_uid      = ENF_OWNER_UID;
    set_attr.va_gid      = ENF_OWNER_GID;

    enf_create(ctx, name, &set_attr);   /* from the copied memfs harness */

    memset(&set_attr, 0, sizeof(set_attr));
    set_attr.va_req_mask = CHIMERA_VFS_ATTR_ACL;
    set_attr.va_set_mask = CHIMERA_VFS_ATTR_ACL;
    set_attr.va_acl      = acl;

    enf_setattr(ctx, name, &set_attr);  /* from the copied memfs harness */
} /* enf_create_file_with_acl */

static void
enf_sids_cb(
    const struct chimera_vfs_cred_sids *sids,
    void                               *private_data)
{
    struct test_ctx *ctx = private_data;

    /* Copy: the resolver only lends its entry for this callback, and the
     * credential below outlives it (see the borrow contract in
     * vfs_cred_sids.h). */
    if (sids) {
        ctx->cred_sids = *sids;
        ctx->cred.sids = &ctx->cred_sids;
    } else {
        ctx->cred.sids = NULL;
    }
    ctx->done = 1;
} /* enf_sids_cb */

/* Build ctx->cred for this caller and attach its resolved SID set. */
static void
enf_resolve_cred(
    struct test_ctx *ctx,
    uint32_t         uid,
    uint32_t         gid,
    uint32_t         ngids,
    const uint32_t  *gids)
{
    chimera_vfs_cred_init_unix(&ctx->cred, uid, gid, ngids, gids);

    chimera_vfs_cred_resolve_sids(ctx->vfs_thread, &ctx->cred,
                                  enf_sids_cb, ctx);
    wait_done(ctx);
} /* enf_resolve_cred */

static void
enf_read_cb(
    enum chimera_vfs_error error_code,
    uint32_t               count,
    uint32_t               eof,
    struct evpl_iovec     *iov,
    int                    niov,
    struct chimera_vfs_attrs *attr,
    void                  *private_data)
{
    struct test_ctx *ctx = private_data;

    (void) count;
    (void) eof;
    (void) iov;
    (void) niov;
    (void) attr;

    ctx->status = error_code;
    ctx->done   = 1;
} /* enf_read_cb */

/*
 * Attempt a one-byte read as ctx->cred.  This goes through chimera_vfs_read,
 * hence the real gate and the real access check -- which is the point of
 * testing here rather than against chimera_acl_access_check directly.
 */
static enum chimera_vfs_error
enf_try_read(
    struct test_ctx *ctx,
    const char      *name)
{
    enf_lookup_open(ctx, name);   /* from the copied memfs harness */

    chimera_vfs_read(ctx->vfs_thread, &ctx->cred, ctx->handle, 0, 1,
                     enf_read_cb, ctx);
    wait_done(ctx);

    chimera_vfs_release(ctx->vfs_thread, ctx->handle);
    ctx->handle = NULL;

    return ctx->status;
} /* enf_try_read */

static void
enf_get_acl_cb(
    enum chimera_vfs_error    error_code,
    struct chimera_vfs_attrs *attr,
    void                     *private_data)
{
    struct test_ctx *ctx = private_data;

    ctx->status = error_code;

    /* va_acl points at backend storage valid only inside this callback, so
     * copy it out here rather than saving the pointer. */
    if (error_code == CHIMERA_VFS_OK &&
        (attr->va_set_mask & CHIMERA_VFS_ATTR_ACL) && attr->va_acl) {
        memcpy(ctx->acl_out, attr->va_acl,
               chimera_acl_size(attr->va_acl->num_aces));
    }

    ctx->done = 1;
} /* enf_get_acl_cb */

/* Read the stored DACL back into `out`. */
static void
enf_get_acl(
    struct test_ctx    *ctx,
    const char         *name,
    struct chimera_acl *out)
{
    enf_lookup_open(ctx, name);

    ctx->acl_out = out;

    chimera_vfs_getattr(ctx->vfs_thread, &ctx->cred, ctx->handle,
                        CHIMERA_VFS_ATTR_MASK_STAT | CHIMERA_VFS_ATTR_ACL,
                        enf_get_acl_cb, ctx);
    wait_done(ctx);

    assert(ctx->status == CHIMERA_VFS_OK);

    chimera_vfs_release(ctx->vfs_thread, ctx->handle);
    ctx->handle = NULL;
} /* enf_get_acl */
```

`enf_create`, `enf_setattr` and `enf_lookup_open` are the create / setattr / lookup-then-open sequences already present in `src/vfs/tests/vfs_enforce_test.c`; lift them with their callbacks and rename to this prefix. Note the read is issued as `ctx->cred` (the test caller), while the create and setattr run as a root credential so the setup itself is never the thing under test -- `chimera_vfs_get_server_cred()` gives one.

Register the test:

```cmake
add_executable(vfs_acl_sid_enforce_test vfs_acl_sid_enforce_test.c)
target_link_libraries(vfs_acl_sid_enforce_test chimera_vfs chimera_vfs_memfs evpl)
add_test(chimera/vfs/acl_sid_enforce_test vfs_acl_sid_enforce_test)
```

- [ ] **Step 2: Run the test**

```bash
sudo ninja -C build/Debug vfs_acl_sid_enforce_test && \
    sudo./build/Debug/src/vfs/tests/vfs_acl_sid_enforce_test
```

Expected: all four cases PASS. If `test_all_opaque_dacl_grants` fails with EACCES, the credential's SID set did not reach the access check -- check that `ctx->cred.sids` is set before the read and that the copy, not the borrowed pointer, is what it points at.

- [ ] **Step 3: Run the full quick tier**

```bash
cd build/Debug && sudo ctest --output-on-failure
```

Expected: green. Per the note in `project_smb_loopback_probe_parallel_flake`, if a posix/smb `loopback_*` case aborts, re-run it serially before attributing it to this change.

- [ ] **Step 4: Run the release build too**

ASan changes timing around the park-and-resume paths, so confirm both configurations.

```bash
sudo ninja -C build/Release
cd build/Release && sudo ctest --output-on-failure -j 8
```

Expected: green.

- [ ] **Step 5: Format and commit**

```bash
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/tests/vfs_acl_sid_enforce_test.c
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/tests/vfs_acl_sid_enforce_test.c
git add src/vfs/tests/vfs_acl_sid_enforce_test.c src/vfs/tests/CMakeLists.txt
git commit -m "vfs: cover SID-only DACL enforcement end to end

Drives the real access gate over memfs: an all-SID DACL grants the caller
whose SID it names, an unresolvable SID matches nobody, a live group SID
grants through a DACL that also holds a dead one, and the stored
descriptor is byte-identical afterwards.

Signed-off-by: Alain Renaud <alain.renaud@quantum.com>"
```

---

### Task 7: Documentation, model coverage, and final verification

**Files:**
- Modify: `src/vfs/sdk/vfs_acl.h:92-99` (the `CHIMERA_PRINCIPAL_SID` comment, now stale)
- Modify: `src/vfs/sdk/chimera_vfs_sdk.h` (SDK version note, if it names the version)

**Interfaces:** none.

- [ ] **Step 1: Correct the now-stale principal comment**

`src/vfs/sdk/vfs_acl.h:92-99` still says a `CHIMERA_PRINCIPAL_SID` "matches no caller during access evaluation". Replace that clause:

```c
    /* A native Windows SID the identity layer could not map to a uid or gid.
     * It is stored and marshalled verbatim so the ACE round-trips losslessly
     * (as NTFS keeps an ACE for a departed domain user).  During access
     * evaluation it is matched against the caller's own resolved SIDs (see
     * chimera_vfs_cred_sids), so a descriptor carrying only bare domain SIDs
     * still enforces; a SID that names no caller we know matches nobody, and
     * it bears on no POSIX mode class either way. */
    CHIMERA_PRINCIPAL_SID     = 3,
```

- [ ] **Step 2: Check whether the SDK version is named in prose**

```bash
grep -rn "version 2\|SDK version" src/vfs/sdk/*.h
```

Update any comment that names SDK version 2 as current (the `_Static_assert` messages on `chimera_principal` and `chimera_ace` in `vfs_acl.h:170-174` say "part of SDK version 2" -- those describe when the layout was introduced, not the current version, so leave them alone).

- [ ] **Step 3: Consider the model**

Per the repo guidance, a gap the model-based tests could not have caught is a prompt to extend the model. Check whether the quint specification covers ACL principals at all:

```bash
grep -rln "acl\|principal\|sid" ext/specs/ 2>/dev/null | head
```

If the specification models ACL evaluation, add a SID-principal case to it so a future regression is caught in the quick tier. If it does not model ACLs at all, that is a larger piece of work: note it in the pull request rather than starting it here.

- [ ] **Step 4: Verify formatting across every file the branch touched**

Match the Makefile's invocation exactly -- no `-l C`, and `--replace` run twice, per the project's uncrustify note.

```bash
for f in $(git diff --name-only arenaud16/main...HEAD | grep -E '\.(c|h)$'); do
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
    uncrustify -c etc/uncrustify.cfg --replace --no-backup "$f"
done
git diff --stat
```

Expected: no diff. If uncrustify changed anything, commit it as a formatting fixup.

Then confirm the check the CI runs is clean for those files:

```bash
for f in $(git diff --name-only arenaud16/main...HEAD | grep -E '\.(c|h)$'); do
    uncrustify -c etc/uncrustify.cfg --check "$f" >/dev/null 2>&1 || echo "FORMAT: $f"
done
```

Expected: no output.

- [ ] **Step 5: Full clean build in both configurations**

```bash
sudo ninja -C build/Release && sudo ninja -C build/Debug
```

Expected: both clean, no new warnings. Watch specifically for a `-Wstringop-truncation` style complaint around the `strncpy` in the negative-cache add -- gcc 11 on Rocky rejects constant-bounded `strncpy` that local gcc accepts. If the bound is constant, use `snprintf(neg->name, sizeof(neg->name), "%s", name)` instead.

- [ ] **Step 6: Full quick tier, both configurations**

```bash
cd build/Debug && sudo ctest --output-on-failure
cd build/Release && sudo ctest --output-on-failure -j 8
```

Expected: green in both.

- [ ] **Step 7: Extended tier for the protocol suites this touches**

Access-control changes are exactly what pjdfstest and pynfs exercise, and a break there would not surface until the nightly Extended run.

```bash
cd build/Debug && sudo ctest -C extended -R "pjd|pynfs|smbtorture" --output-on-failure
```

Expected: no new failures against the branch point. Per `project_pynfs_flake_triage`, check any failure's log for "Chimera daemon DIED" or an io_uring ENOMEM before treating it as a real regression; `EVPL_IO_URING_ENTRIES=1024` works around the local ENOMEM flake.

- [ ] **Step 8: Commit the documentation changes**

```bash
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/sdk/vfs_acl.h
uncrustify -c etc/uncrustify.cfg --replace --no-backup src/vfs/sdk/vfs_acl.h
git add src/vfs/sdk/vfs_acl.h
git commit -m "vfs: correct the native-SID principal comment

It still said a SID principal matches no caller during access
evaluation, which stopped being true when evaluation started matching it
against the caller's own resolved SIDs.

Signed-off-by: Alain Renaud <alain.renaud@quantum.com>"
```

- [ ] **Step 9: Open the pull request**

```bash
git push -u arenaud16 HEAD
gh pr create --repo chimera-nas/chimera --base main \
    --title "vfs: enforce ACEs that carry only a native Windows SID"
```

The body should cover: the problem (a descriptor written by another SMB stack enforces nothing, and a non-empty ACL suppresses the mode fallback, so every non-root caller loses READ_DATA), the approach (resolve the caller to its SID set rather than resolving each ACE, which needs no ACL copy and no change to the stored descriptor), the SDK version bump and why, and the NFS first-request caveat. No "Test plan" section.

---

## Notes for the implementer

- **Downstream follow-up, not part of this branch.** The downstream out-of-tree module carries an 8-byte private identity trailer inside each ACE purely to smuggle the numeric identity past this gap. Once this merges, that trailer can be retired. It lives in the downstream tree, so it is separate work on a separate branch.
- **What was deliberately not done.** `chimera_vfs_access_check()` keeps its synchronous signature, `ace_applies()` keeps its parameters, and no access-check call site changes. That is the payoff of resolving the caller rather than the ACL: the enforcement fix lands in one `switch` arm.
- **If the SMB thread expression in Task 4 step 3 does not compile**, the VFS thread is reachable from the compound in every other SMB proc; copy the expression from `src/server/smb/smb_proc_security.c`, which calls `chimera_vfs_identity_resolve` from the same context.
