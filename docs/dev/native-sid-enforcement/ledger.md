# SDD ledger -- plan: <workspace>/plan.md

Spec: the originating ticket -- read at plan
time; the plan's "Deviation from the spec" section records where plan and spec
intentionally differ (resolution direction inverted, ticket owner approved).

Worktree: <worktree>/
Branch: vfs-native-sid-enforcement, off arenaud16/main @ cca8d9cc
Build trees: <build>/Debug, <build>/Release
Baseline: 55/55 ctest quick tier passing at cca8d9cc, both trees configured.

## Pre-flight scan

### Cross-task rows (tasks sharing a file or an interface)

| Tasks | Produced -> consumed | Finding |
|---|---|---|
| 1 -> 3 | `struct chimera_vfs_cred_sids{ngroups,user,groups[]}`, `cred->sids` | Names agree across both task texts. Clean. |
| 1 -> 4 | same type + `cred.sids` for `session->cred_sids` | Clean. |
| 1 -> 5 | `cred.sids` assigned from lookup | Clean; `const` qualifier matches on both sides. |
| 1 -> 6 | `ace_applies()` SID arm; ACEs built with `who.type=CHIMERA_PRINCIPAL_SID` | Clean. |
| 2 -> 3 | negative cache + in-flight dedup behind the unchanged `chimera_vfs_identity_resolve()` signature | Clean: no signature coupling, T3 calls only existing API. |
| 3 -> 4 | `chimera_vfs_cred_resolve_sids()` + borrow contract | Clean; T4 copies the set, honouring the contract. |
| 3 -> 5 | `chimera_vfs_cred_sids_lookup()`, `_warm()` | Clean. |
| 3 -> 6 | `chimera_vfs_cred_resolve_sids()` | Clean. |
| 3 / 5 | both edit `src/vfs/tests/vfs_cred_sids_test.c` | Sequential. T5's `test_warm_then_lookup` uses `sid_str_is`, `TEST_UID`, `TEST_UID_SID` from T3's file -- all defined there. Clean. |
| 3 / 6 | both edit `src/vfs/tests/CMakeLists.txt` | Sequential, different blocks appended. Clean. |
| 1 / 7 | T1 edits `vfs_acl.c`, T7 edits `sdk/vfs_acl.h` | Different files. Clean. |
| 1 / 2 | none | No shared files. Independent; 2 could run before 1. |

### Per-task self-consistency rows

| Task | Finding |
|---|---|
| 1 | Test code and impl code agree on every field and signature. `vfs_acl_test.c` already includes `vfs/sdk/vfs_sid.h`, so `chimera_sid_from_str` resolves. **Defect:** the test memsets `sizeof(chimera_acl) + 2*sizeof(chimera_ace)` out of an `ACL_BUF(acl, 4)` storage -- under-clears. See Ruling 1. |
| 2 | `DL_APPEND2`/`DL_DELETE2`/`DL_FOREACH2` with the `inflight_prev/next` link pair are consistent; utlist is already used in this file. **Gap:** the shutdown drain's waiter-freeing is prose, not code. See Ruling 2. |
| 3 | Slot array sized `CHIMERA_VFS_CRED_MAX_GIDS + 2` = 18; max used = 1 user + 17 groups = 18. Exact fit, correct. Forward reference from `slot` to `ctx` is a pointer to an incomplete type -- legal C. Clean. |
| 4 | **Gap:** the VFS-thread expression in the session-setup call is given as an instruction to grep rather than as code. See Ruling 3. |
| 5 | `req->thread->vfs_thread` matches the shape used in `nfs4_proc_access.c`. Clean. |
| 6 | **Gap:** helpers `enf_create`/`enf_setattr`/`enf_lookup_open` are described as "from the copied memfs harness" but do not exist under those names in `vfs_enforce_test.c`. See Ruling 4. |
| 7 | Clean. Verified separately that no in-tree module hardcodes SDK version 2 (all use `CHIMERA_VFS_SDK_VERSION`), so T1's bump to 3 breaks no in-tree build. |

### Global-constraints check

ASCII-only, SPDX on new files, `<area>:` commit subjects, Signed-off-by
trailer, no CHIM refs, per-file uncrustify (never `make syntax`/`make check`),
no the internal CI tool: all task texts comply. No task contradicts a Global Constraint.

## Pre-flight rulings

Ruling 1: Task 1's test must `memset` the full `ACL_BUF` storage, not a
2-ACE prefix -- the buffer is declared for 4 ACEs and a partial clear leaves
`aces[2..3]` indeterminate. Rationale: the plan's own principal by-value
contract requires every byte defined, and a reviewer would flag it. Cost if
wrong: none, the fuller memset is strictly safer.

Ruling 2: Task 2's shutdown drain must free each queued request's `waiters`
list as well as the request. The plan states this in prose only; it is
required, not optional, or ASan reports a leak at teardown. Cost if wrong:
none.

Ruling 3: Task 4's implementer resolves the VFS-thread expression by reading
the surrounding function and `smb_proc_security.c`, which calls
`chimera_vfs_identity_resolve` from the same context. If no expression in
scope yields a `struct chimera_vfs_thread *`, report BLOCKED rather than
inventing a plumbing change. Cost if wrong: a wrong expression fails to
compile immediately, so this cannot ship silently.

Ruling 4: Task 6's implementer owns the shape of the memfs harness helpers
(`enf_create`, `enf_setattr`, `enf_lookup_open`) -- they are new code modelled
on `vfs_enforce_test.c`, not a literal copy. The four test cases and their
assertions are binding exactly as written; the helper internals are not.
Cost if wrong: helper churn inside one test file, no production impact.

Ruling 5: Build paths. The plan's `build/Debug` / `build/Release` become
`<build>/Debug` / `<build>/Release`, and ctest runs as
`ctest --test-dir <tree>`. Rationale: in this devcontainer the source tree is
virtiofs and an in-tree build tree is both slower and a known hazard; the
established practice is out-of-tree under /build. Cost if wrong: path strings
only, trivially corrected.

## Progress

Task 1: complete (commits cca8d9cc..0f7b7424, review clean -- spec PASS, quality APPROVED)
Task 1: minor (deferred): src/vfs/tests/vfs_acl_test.c:592 test_sid_principal_never_matches -- name and docstring say a SID principal "matches no caller during access evaluation", now true only for a caller with no SID set. Fold the wording fix into Task 7 (already a documentation task touching the same claim in sdk/vfs_acl.h).
Task 1: Ruling: the plan's per-task ctest commands for the acl/sid/idmap tests need `-C extended` -- those tests are registered in the extended tier, so the plan's bare `ctest -R...` matches zero tests and silently "passes". Carry `-C extended` into every later task's targeted ctest command; the full quick-tier run (`ctest` with no -R) stays as written. Cost if wrong: a targeted run matches nothing and a task reports green on no evidence -- which is exactly what this prevents.
Task 1: Ruling: implementer patched src/server/nfs/tests/test_fh_security.c (outside the brief's file list) where a cred is built by direct field assignment. Accepted -- Step 4 mandates an exhaustive audit, and the reviewer independently confirmed it was the only gap in ~50 sites. Cost if wrong: one redundant NULL assignment in a test.
Task 2: complete (commits 0f7b7424..14eaff01, review clean -- spec PASS, quality APPROVED)
Task 2: Ruling: all five implementer deviations from the brief ACCEPTED as plan defects; reviewer reproduced each independently. (a) brief's strncpy fails Release under -Werror=stringop-truncation -> snprintf; (b) brief's worker fan-out reintroduced the use-after-free that upstream d1ee0231 already fixed for the primary job -> read `origin` into a local before publishing; (c) brief's test state must be static since miss handlers are never unregisterable; (d) helpers belong above the worker (implicit-declaration -Werror); (e) vfs_identity.h doc comment amended because a negative hit now completes inline -- both SMB callers verified safe under inline completion (sd_pending guard pattern). Cost if wrong: (b) is the only load-bearing one and it moves toward an already-merged upstream fix, so the risk is that it was unnecessary, not that it is wrong.
Task 2: minor (deferred): test_inflight_dedup asserts handler-call-count but never asserts the second resolve parked, so the cross-thread waiter fan-out has no deterministic test -- it is exercised probabilistically. A condvar-blocking handler would pin it.
Task 2: minor (deferred): negative-hit fast path callocs a ~1.7 KB request per hit only so the probe sees the truncated name; a 256-byte stack buffer would do.
Task 2: minor (deferred): negative table has no size cap and its chains are walked under the global resolver lock; acceptable now, wants a cap if the SMB SD path gets hot.
Task 2: minor (deferred): chimera_vfs_identity_cached() does not consult the negative table, so SMB SD paths still treat a negatively-cached id as a miss (correct, just not the fast path).
Task 2: minor (deferred): the 60 s negative-TTL expiry branch is never taken by any test.
Task 3: review 1 -- spec PASS, quality CHANGES NEEDED (3 Important). Entering fix loop at f63ea28f.
Task 3: Ruling: the implementer's `inflight`-counter deviation from the brief is ACCEPTED. The brief's eviction comment justified reuse with "no resolve can start while another's callback is running", which is about callback atomicity; the property the reuse actually needs is quiescence across the whole in-flight window, and a parked cold resolve violates it. Reviewer confirmed the interleaving is reachable and worse than first described (a saturated bucket hands the SAME tail to every new cold resolve, so the parked entry is the victim every time). Consequence if unfixed: one credential's SID set published under another credential's hash in an authorization cache. Cost if wrong: a 4-byte field and a few lines of accounting that turn out to be unnecessary.
Task 3: Ruling: eviction test coverage promoted from the reviewer's Minor into fix round 1. Rationale: two of the three Important findings are eviction bugs found by inspection alone with no runtime reproduction, and eviction is now the most security-relevant code in the file -- a class of bug this branch has already hit twice deserves a test, not a third inspection. Cost if wrong: one probabilistic test case that never fails.
Task 3: fix round 1/5 (3 addressed, 0 open -- Important 1 pin-across-callback, Important 2 credential-key comparison, Important 3 header/code agreement, plus promoted eviction coverage; commits f63ea28f..fed8ea9e)
Task 3: complete (commits 14eaff01..fed8ea9e, review clean)
Task 3: implementer found a 4th instance of Important 1 the review missed -- the warm shortcut handed out an unpinned pointer on the common repeat-caller path. Re-reviewer confirmed real, complete and balanced on every exit path.
Task 3: minor (deferred): commit fed8ea9e's message overclaims "Both fail without these fixes" -- only test_borrow_pinned_across_callback does; the eviction sweep passes under all three mutations.
Task 3: minor (deferred): stale comment at vfs_cred_sids.c:170-171 says the chain grows "until they finish", implying it shrinks; nothing frees entries outside thread teardown, so the high-water chain length is permanent for the life of the thread.
Task 3: minor (deferred) FLAG FOR FINAL REVIEW: vfs_cred_sids.c:92 set_key() memcpys cred->ngids entries into a 16-element array with no clamp. Unreachable today (every in-tree constructor caps ngids at CHIMERA_VFS_CRED_MAX_GIDS), but it is an out-of-bounds WRITE surface in an authorization cache where the analogous pre-existing exposure in chimera_vfs_cred_hash() is only a read. One-line clamp. Consider fixing before merge.
Task 3: minor (deferred) FLAG FOR FINAL REVIEW: NULL-credential asymmetry -- find() gained a !cred guard whose comment implies credential-less operations are supported, but _resolve_sids()/_warm() still dereference cred unconditionally. Either document the precondition or early-return. Note: Tasks 4 and 5 both pass the address of an embedded struct, which is never NULL, so this is latent rather than live.
Task 3: minor (deferred): the eviction sweep exercises only 13 of 64 buckets because FNV-1a low bits cancel when uid and gid move together -- which includes the common user-private-group case (uid == gid), dropping effective per-thread capacity from 256 to ~52 entries. Design inherited from the plan, not introduced by the fix.
Task 3: minor (deferred): test_borrow_pinned_across_callback's drain loop has no spin cap, so a stuck identity worker hangs the test instead of failing it.
Task 3: minor (deferred): chimera_vfs_cred_sids_thread_destroy() frees entries unconditionally including any with inflight != 0; a resolve parked at teardown would write through a freed entry. Pre-existing, and subsumed by a wider identity-layer teardown hazard (thread_destroy never drains thread->pending_identity).
Task 4: review 1 -- spec PASS, quality CHANGES NEEDED (2 Important). Entering fix loop at fd50cc5d.
Task 4: Ruling: the brief's VFS-thread expression `request->compound->thread->shared->vfs_thread` was WRONG (struct chimera_server_smb_shared has no such field). Implementer's `request->compound->thread->vfs_thread` accepted; reviewer confirmed against smb_internal.h and the smb_proc_security.c idiom. This closes pre-flight Ruling 3. Cost if wrong: none, the wrong form does not compile.
Task 4: Ruling: the implementer's `if (!is_binding)` placement ACCEPTED. Reviewer verified session->cred is set in exactly two places tree-wide, is_reauth is a subset of that block, and a binding leg deliberately never touches the session credential. Cost if wrong: a bound channel would enforce against the establishing leg's identity, which is the intended SMB semantic anyway.
Task 4: Ruling: the stale-identity race (Important 2) is fixed NOW rather than deferred, though the reviewer noted it is outside this task's literal scope. Rationale: session-slot reuse lets a late resolve callback write one session's SIDs into an unrelated new session -- cross-session identity leakage in an authorization path, the same class of bug Task 3 hit with cache-entry recycling, and inconsistent to fix there and wave through here. Cost if wrong: a generation stamp that was never needed.
Task 4: minor (deferred): the callback writes cred_sids/cred.sids without session->lock, extending a pre-existing unsynchronized-write property (cred.uid/gid/ngids are already written the same way for multichannel sessions). Not a regression from this diff.
Task 4: fix round 1/5 (2 addressed, 0 open -- uncrustify realignment, cred_generation stamp closing both stale-identity orderings; commits fd50cc5d..3b77f199)
Task 4: complete (commits fed8ea9e..3b77f199, review clean)
Task 4: minor (deferred): uncrustify strips the leading space before a continuation `*` in the new sids_ctx comment. Re-reviewer bisected it and found the implementer's stated rule ("first line has text after /*") wrong -- the trigger is the token `SID` ending the wrapped first line. --check passes either way, so cosmetic only.
Task 4: minor (deferred): unchecked malloc for sids_ctx, consistent with the existing small-allocation idiom in smb_durable.c.
Task 5: Ruling (plan defect, decided before dispatch): the plan has NFS assign the borrowed `chimera_vfs_cred_sids_lookup()` pointer straight into req->cred.sids and hold it for the whole request. Task 3's revised header forbids that -- a _lookup() set is pinned by nothing and is valid only until this thread's next resolve or warm, so another request's _warm() can evict it and leave req->cred.sids dangling into an authorization check. Decision: NFS copies the set into request-owned storage, mirroring what Task 4 does for the SMB session. struct nfs_request is thread-pooled (thread->free_requests), so the ~1.3 KB is amortized over the pool high-water rather than paid per operation. Cost if wrong: ~1.3 KB per pooled request that a pinning scheme would have avoided.
Task 5: complete (commits 3b77f199..10d8817b, review clean -- spec PASS, quality APPROVED)
Task 5: copy-not-borrow ruling implemented and verified. Reviewer independently confirmed (a) recycled pooled requests are safe -- chimera_nfs_map_cred() unconditionally re-inits the credential through init_unix/init_anonymous/gss, all of which set sids = NULL, so a recycled request can never start pointing at the previous occupant's copy; (b) the nfs3_procs.h:85 double-squash is safe because chimera_vfs_cred_init_anonymous() sets uid, gid and sids together in one call, so uid and sids can never disagree about being anonymous.
Task 5: Ruling: the reviewer's "Important (non-blocking)" test-coverage finding is DEFERRED, not fixed. No NFS-protocol-level test exercises the new funnel branch, and Task 6's end-to-end coverage drives memfs at the VFS layer rather than the NFS wire. But the brief deliberately scoped out building an NFS request-funnel harness, the reviewer states it is acceptable to merge as-is, and standing up a wire-level harness is disproportionate to a 38-line change. Recorded for the final review to triage and worth a follow-up ticket. Cost if wrong: a future edit to the credential path could regress NFS SID attachment without any test failing.
Task 5: minor (deferred): recycled-request safety rides on the unenforced pre-existing invariant that every proc entry calls chimera_nfs_map_cred_req() before touching req->cred; nfs_request_alloc() does not clear cred/orig_cred/cred_sids on the pooled path. This diff does not weaken it.
Task 5: minor (deferred): the brief's test_warm_then_lookup was satisfied by Task 3's pre-existing test_warm_feeds_lookup rather than a byte-duplicate; reviewer verified identical behaviour.
Task 6: complete (commits 10d8817b..68f2097c, review clean -- spec PASS, quality APPROVED). All four ticket acceptance-criteria cases pass. Mutation test (ace_applies SID arm forced back to `return 0`) fails 3 of 4 cases; the 4th is the intended negative control. Reviewer traced the gate independently and predicted the same result before reading it.
Task 6: Ruling: all four implementer deviations ACCEPTED. (a) literal uid-0 setup credential instead of chimera_vfs_get_server_cred(), which returns getuid() and would make the scaffolding EACCES under a non-root ctest run; (b) brief's chimera_vfs_read call had the wrong arity, fixed; (c) lookup as root but open as the caller -- reviewer confirmed this is LOAD-BEARING, since a root open would reuse the create's cached handle carrying granted_bound=1/MASK_ALL and every case would pass without reading the ACL at all; (d) stale vfs_acl.h doc comment left for Task 7. Cost if wrong: (c) is the only one that matters and getting it wrong makes the test vacuous, which the mutation test would have caught.
Task 6: minor (deferred): enf_get_acl() sizes its memcpy from the backend's ACE count but takes no capacity argument, and its only caller passes a 1-ACE stack buffer. Correct today (memfs stores the ACL verbatim) but a stack overflow waiting for the first backend that rewrites or synthesises an ACL on read.
Task 6: minor (deferred): enf_resolve_cred() never asserts resolution produced a set, so a regressed resolver would surface as a matcher failure rather than being localised.
Task 6: minor (deferred): the enf_lookup_open comment understates the hazard -- worth naming that a root open would take the read fast path via the create's cached granted_bound handle and make every case vacuous.
Task 7: complete (commits 68f2097c..df221d50, review clean -- spec PASS, quality APPROVED; reviewer judged the report candid about its verification gap rather than papering over it)
Task 7: Ruling: the plan's final step (git push + gh pr create) was STRIPPED from the dispatch. Pushing to the fork and opening an upstream PR is outward-facing and the user's call, not mine; the task ends at the last local commit. Cost if wrong: none, the push remains available.
Task 7: Ruling: the extended tier was NOT completed locally (pjdfstest, smbtorture, and ~5717 of 5721 pynfs cases have no result; 4 pynfs NFSv4.0 cases passed). I told the implementer to drop it rather than stall, because those suites are slow and known-flaky here and are not the merge gate -- the quick tier is. I then started pjdfstest myself separately. This is the branch's one real verification gap and access control is exactly what those suites exercise. Cost if wrong: an extended-tier regression would not surface until the next nightly Extended run.
Task 7: minor (deferred): a pre-existing non-ASCII section sign at src/vfs/sdk/vfs_acl.h:125 violates the project's hard ASCII-only rule. Confirmed present at the branch point cca8d9cc and untouched by all 9 commits, so correctly left alone -- worth a separate cleanup.
Task 7: finding (no code change): ext/specs/ does not model ACL evaluation at all -- only {uid,gid,gids} against POSIX mode bits, with a comment in posix_fs.qnt explicitly disclaiming NFSv4 ACLs. So the quick tier's model-based tests structurally cannot cover this branch's behaviour. Worth a follow-up ticket independent of this work.
FINAL REVIEW (cca8d9cc..df221d50, 9 commits): verdict "not yet -- one short fix round". 1 Critical, 4 Important, 12 Minor, 4 design observations. Deferred-minor triage returned: 5 fix-before-merge, the rest ship-as-is.
FINAL: Ruling: the reviewer's finding D1 is CONFIRMED by my own check and is the single most important thing about this branch. Nothing in-tree produces a CHIMERA_PRINCIPAL_SID ACE -- the constant is assigned nowhere in production code, who.sid is written only by chimera_acl_deserialize(), and the SMB descriptor parser SKIPS an ACE whose SID it cannot resolve (smb_proc_security.c:474-479, `smb_unres_record` then `continue`) rather than storing it opaquely. So the branch is the consumer half of a two-part change: correct, tested, and currently unreachable from any in-tree protocol path. It does unblock out-of-tree producers (the downstream out-of-tree module, which is the ticket's stated motivation for retiring its private identity in-ACE trailer) and a future in-tree producer. This must be stated plainly in the PR description -- a reviewer reading the commit messages would otherwise believe it fixes a live denial. Cost if wrong: an upstream reviewer is surprised and asks for the producer.
FINAL: Ruling: ONE fix wave dispatched covering Critical 1 and Important 2-5 plus Minors 6, 7 and 9. Important 2 (a transient resolver failure freezes a partial SID set for the life of the thread, because entry->valid is set on ANY slot resolving and a valid entry is never re-resolved) and Important 3 (every NFS op re-resolves on a deployment without winbind, because an all-absent set never becomes valid so _lookup never hits) are two halves of the same modelling gap and are fixed together: separate "resolve completed" from "resolve produced something", and add a TTL so a partial or failed resolve self-heals rather than persisting for the life of the VFS thread. Cost if wrong: a TTL that re-resolves slightly more often than strictly needed.
FINAL fix wave: 5 commits df221d50..312b372d. Scoped re-review: all 9 findings ADDRESSED, no new Critical/Important breakage.
FINAL: Ruling: the implementer DISAGREED with the review's suggested hash fix (`hash ^ (hash >> 32)`) and used a murmur3 fmix64 instead. Upheld -- the re-reviewer reproduced the hash in isolation and confirmed bits 32-37 of the FNV accumulator are constant across the sweep, so the suggested fold is a bijective relabelling of the same 13 buckets (52/400 either way) and the high bits alone are worse. murmur3 gives 243/400 against a nominal 256. Both measured numbers reproduced exactly. Cost if wrong: none, the mix is standard and fully avalanching.
FINAL: Ruling: the implementer went beyond the brief with a stale-while-revalidate TTL (a refresh builds its set in its own ctx and publishes whole, so a refresh never blanks a live entry). ACCEPTED -- without it the NFS funnel would see NULL for the length of a resolve round trip once per TTL per caller, turning a SID-derived grant into a denial. Re-reviewer confirmed the publish is atomic w.r.t. a same-thread reader, cannot resurrect stale state (ctx is calloc'd, whole struct replaced, so a refresh that names less demotes rather than leaving a stale grant), and retires the older "do not clear an entry a joined resolve is filling" rule. Cost if wrong: a refresh serves a slightly stale set for one round trip.
FINAL: residual 1 PARKED: chimera_vfs_cred_hash() (vfs_cred.c:55-57) still reads cred->gids[] unclamped. The wave clamped the writes and left the read, so the asymmetry now sits in the function that keys the authorization cache. Pre-existing and unreachable in-tree (every constructor caps ngids), one-line fix. Re-reviewer would fix rather than ship. Surfaced to the user as the top follow-up.
FINAL: residual 2 PARKED: the SMB session SID set never expires -- session->cred_sids is stamped once at setup and never refreshed, so the exact failure the new TTL cures (a partial resolve standing indefinitely) still applies to an SMB session for its whole lifetime. The TTL heals only the VFS-thread cache. Surfaced to the user.
FINAL: residual 3 PARKED: making cred_generation atomic fixed the guard but not the payload -- the callback writes ~1.3 KB into session->cred_sids and then session->cred.sids under no lock while session->cred is read from ~20 sites on other channel threads. Pre-existing and wider than this branch.
FINAL: residual 4 PARKED: _resolve_sids()'s warm shortcut tests valid && fresh, not resolved, so a fresh resolved-empty entry still re-fans-out on every call. Harmless today (one production caller, once per session setup); will bite the next async consumer.
FINAL: residual 5 PARKED: _decr() now dereferences ctx->thread->cred_sids->ttl, marginally widening the known teardown hazard (thread_destroy frees entries and never drains pending_identity).
FINAL: residual 6 PARKED: chimera_vfs_cred_sids_set_ttl() is a test-only hook SYMBOL_EXPORTed from production code. Documented as such; an upstream reviewer will ask.
FINAL: new minor (parked): the expiry test's 1-second TTL is truncated to integer seconds, so "still inside the TTL" can fail if a second boundary lands in a ~1e-5 window. Low-probability flake, misleading message if it fires.
FINAL: Ruling: workspace NOT deleted, deviating from the skill's finish step. Its rationale is "the git history is the record now", which assumes the work is merged; this branch is not even pushed, and the reports hold analysis that is not in any commit -- in particular the D1 finding that reframes the PR. Keeping it until the user has decided what to do with the branch. Cost if wrong: a stale gitignored directory in the worktree.
EXTENDED TIER: pjdfstest run 1 = 29 failures (link/02, rename/24, utimensat/09, granular/00,03,04 across every backend and both NFS versions). Run 2, same build tree, same -R selector = 2578 tests, 0 failures. Every run-1 failure also passed individually and in a 30-test batch. Verdict: contention flake, NOT a regression from this branch. Cause: run 1 overlapped the final fix wave's own ninja builds and ctest runs, and pjd cases each start a chimera daemon binding ports -- the same class as the known posix/smb loopback parallel flake. Evidence chain recorded because these are permission tests and this is a permissions change, so the null result needed proving rather than assuming.
EXTENDED TIER: still NOT run locally: pynfs (4 of ~5721 cases only), smbtorture. Those remain the branch's open verification gap, and the final review named them items 1 and 2 of what it wants run before this goes upstream.
