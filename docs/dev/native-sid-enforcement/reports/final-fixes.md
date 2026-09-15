# Final whole-branch review: fix wave

Branch `vfs-native-sid-enforcement`, base `cca8d9cc`, pre-wave tip `df221d50`.
All nine findings addressed in five commits on top of `df221d50`.

| SHA | Subject |
| --- | --- |
| `26532a83` | vfs: drop the borrowed SID set from the delete-on-close credential |
| `c7c4f0d1` | vfs: spread the credential SID cache across its whole table |
| `cd5038be` | vfs: bound and harden the credential SID cache inputs |
| `351f6a85` | vfs: age out credential SID sets and record a resolve that named nothing |
| `312b372d` | smb: make the session credential generation atomic |

## Critical 1 -- dangling `sids` on the delete-on-close credential (FIXED, `26532a83`)

`chimera_vfs_open_cache_set_doc()` (`src/vfs/vfs_open_cache.h:1043`) now clears
`handle->doc_cred.sids` immediately after the by-value copy, with a comment
giving the reason: the deferred unlink runs at last close, routinely after the
SMB session that owns `cred_sids` has been pooled or freed, and that path has
never matched SID ACEs, so NULL is both correct and free. No backing copy was
added (the reviewer's 1.3 KB/handle objection stands: `sizeof(struct
chimera_vfs_cred_sids)` is 1300 bytes, since `sizeof(struct chimera_sid)` is
72).

Latent cases confirmed latent, as the reviewer suspected:
`src/vfs/nfs/nfs3_open_state.h` `silly_remove_cred` (:39) and `open_cred` (:50)
reach exactly one consumer, `chimera_nfs_init_rpc2_cred()`
(`src/vfs/nfs/nfs_internal.h:981-1013`), which reads `flavor`, `uid`, `gid`,
`gids` and nothing else. Traced every use: `nfs3_close.c:87`,
`nfs3_read.c:87`, `nfs3_write.c:102`, `nfs3_commit.c:94`, `nfs3_setattr.c:91`,
`nfs3_allocate.c:142/252/306` (all via `chimera_nfs3_allocate_cred()`). A
comment was added at each field noting the copied pointer is deliberately never
dereferenced and that anything matching SID ACEs off these credentials must
copy the set first. No code change.

(`src/vfs/nfs/nfs4_open_state.h:49` declares a `silly_remove_cred` that is
never read or written anywhere -- pre-existing dead field, left alone.)

## Important 4 -- ~52 entries instead of 256 (FIXED, `c7c4f0d1`)

Root cause confirmed, but **the suggested remedy does not work** and was
replaced -- flagged for adjudication.

`chimera_vfs_cred_hash()` is a word-wise FNV-1a over 3-4 words. Simulated the
exact hash over the eviction test's 400 credentials (uid 700000+i,
gid 800000+i) and reproduced the observed number exactly:

| bucket index | buckets used (of 64) | entries retained (of 400) |
| --- | --- | --- |
| `hash % 64` (before) | 13 | 52 (simulated 52, measured 52) |
| `(hash ^ (hash >> 32)) % 64` (suggested fold) | 13 | 52 (simulated **and measured**: no change) |
| top 6 bits (`hash >> 58`) | 2 | worse |
| murmur3 finalizer, then `% 64` (**applied**) | 64 | 243 (simulated 243, measured 243) |

The fold is a no-op here because bits 32-37 of the FNV accumulator are constant
across such a sweep, so it lands on exactly the 13 buckets the low bits do; the
high bits are worse still, because three multiplies over small inputs barely
move the top of the accumulator. `chimera_vfs_cred_sids_bucket()` therefore
avalanches the hash (murmur3 64-bit finalizer) before taking the index, at both
former `% CHIMERA_VFS_CRED_SIDS_BUCKETS` sites.

**Eviction retention: 52 of 400 before, 243 of 400 after** (nominal capacity
64 buckets x 4 = 256). `vfs_cred_sids_test` now asserts a loose floor
(`cached > TEST_EVICT_N / 4`) so the property is pinned without encoding the
private bucket count or chain depth.

## Important 2 + 3 -- "resolved to nothing" vs "never resolved", and no TTL (FIXED, `351f6a85`)

Shape chosen:

* `struct chimera_vfs_cred_sids_entry` now carries `resolved` (a resolve ran to
  completion, whatever it found), `valid` (it named at least one SID) and
  `expiration`.
* `CHIMERA_VFS_CRED_SIDS_TTL` is 60s, matching `chimera_vfs_user_cache`'s
  60-second expiry sweep (`src/vfs/vfs_user_cache.h:261`) and
  `CHIMERA_VFS_IDENTITY_NEGATIVE_TTL` (`src/vfs/vfs_identity.c:66`). The
  comment says why the number is what it is: by the time an entry expires, the
  negative that spoiled it has expired too, so the retry asks the handlers
  again rather than replaying the same refusal.
* New `chimera_vfs_cred_sids_probe(thread, cred, &sids)` reports both facts in
  one lookup -- non-zero means "an answer is cached or on its way, do not
  resolve", `*sids` is the set or NULL. `chimera_vfs_cred_sids_lookup()` is now
  a thin wrapper (unchanged signature, unchanged meaning).
* `chimera_nfs_map_cred_req()` (`src/server/nfs/nfs_common.h`) uses the probe
  and warms only when it returns 0, so a deployment with no SID source stops
  paying a `1 + ngids` fan-out per request. The set is copied before `warm()`
  is called, because warming can recycle the entry it points into.
* A resolve already in flight also answers "do not resolve", which additionally
  stops every request arriving during a caller's first (parked) resolve from
  stacking a fan-out of its own -- that storm existed before this wave.

One deliberate design addition beyond the brief, because a naive TTL introduces
a regression: a resolve now builds its set in its own context (`ctx->set`) and
moves it into the entry whole at the join, instead of writing through to
`entry->sids` as lookups complete. Without that, a refresh would blank the
entry for the duration of an identity round trip, and every request from that
caller in that window would be evaluated with `sids == NULL`, i.e. *denied*,
once per TTL. Publishing whole also means a refresh that comes back with less
than the last one replaces it rather than leaving a stale grant standing
(fail-closed preserved), and it retires the subtle "do not clear an entry a
joined resolve is filling" rule -- two resolves no longer share a workspace.
`chimera_vfs_cred_sids_probe()` serves the previous set while a refresh is
pending, so nothing served is ever older than one TTL plus one resolve.

**The `inflight` pin is untouched.** It still pins the entry itself against
recycling for the duration of a resolve and of a callback; the pin test passes
unchanged.

`chimera_vfs_cred_sids_set_ttl()` was added (documented as existing for the
unit test) so expiry can be exercised without a one-minute test.

### Tests added (`src/vfs/tests/vfs_cred_sids_test.c`)

* `test_probe_distinguishes_empty_from_unseen` -- unseen credential: probe 0 /
  NULL; while its resolve is parked: probe non-zero / NULL (coalescing); after
  it completes empty: probe non-zero / NULL, and `_lookup()` still NULL.
  Fails without the `resolved` flag.
* `test_expiry_refreshes_a_partial_set` -- TTL shortened to 1s; a credential
  whose gid is nameable and whose uid is not resolves partial; the uid is then
  taught to the identity layer via `chimera_vfs_add_user()` (the user cache is
  probed ahead of the negative table, so this beats the 60s negative entry);
  inside the TTL the partial answer is still handed back with no re-resolve;
  after the TTL the probe returns 0 *and still hands back the stale set*
  (stale-while-revalidate), and the next resolve heals it to the full set.
  Fails without the TTL.

## Important 5 -- unclamped copy into a fixed array (FIXED, `cd5038be`)

`chimera_vfs_cred_sids_ngids()` clamps to `CHIMERA_VFS_CRED_MAX_GIDS`; used by
the `memcpy` in `set_key()`, the `memcmp` in `key_eq()`, and the group-slot
count in `chimera_vfs_cred_resolve_sids()` (which also stops `1 + ngids`
wrapping to 0 at `UINT32_MAX`). The unclamped `ngids` is still what decides
identity, so credentials differing only above the clamp remain distinct
entries.

Note for the reviewer: `chimera_vfs_cred_hash()` (`src/vfs/vfs_cred.c:55-57`)
has the same unclamped read loop over `cred->gids[]`. That is the pre-existing
read overflow the finding refers to; it is shared with the open-handle cache
and was left alone as out of scope for this wave. Worth a follow-up.

## Minor 6 -- `cred_generation` races (FIXED, `312b372d`)

`session->cred_generation` is now `_Atomic uint64_t` (matching
`enc_nonce_counter` on the same struct), bumped with `atomic_fetch_add()` at
`smb_internal.h:2172` and `:2248` and read with `atomic_load()` at
`smb_proc_session_setup.c:133`. The lock-free bump in session setup now stamps
the resolve context with the value its own increment produced
(`atomic_fetch_add(...) + 1`) rather than re-reading the counter, so a
concurrent bump on another channel cannot split the bump from the stamp.

## Minor 7 -- NULL-credential asymmetry (FIXED, `cd5038be`)

Chose "handle NULL everywhere": `chimera_vfs_cred_resolve_sids()` (and
therefore `_warm()`) now completes inline with no set when `cred` is NULL,
matching what `_find()` / `_lookup()` already did. The `_find()` comment was
rewritten to state the shared contract instead of implying one; the header
documents it.

## Minor 9 -- stale comment (FIXED, `cd5038be`)

The eviction comment no longer implies an over-long chain shrinks back. It now
says nothing outside `chimera_vfs_cred_sids_thread_destroy()` frees an entry,
so a chain's high-water length is permanent for the life of the thread, and
that entries past the bound are recycled like any other once their holders
drop -- memory, not correctness. The TTL work did not change this (entries are
re-resolved in place, never freed).

## Verification

```
sudo ninja -C <build>/Debug                     -> clean
sudo ninja -C <build>/Release                   -> clean

sudo <build>/Debug/src/vfs/tests/vfs_cred_sids_test
  PASS: synchronous lookup misses on an unseen credential
  PASS: credential resolves to its SID set and caches per thread
  PASS: an all-inline resolve completes before the call returns
  PASS: warm leaves the set where a synchronous lookup finds it
  PASS: the probe tells a resolved-empty credential from an unseen one
  PASS: an expired entry is re-resolved, and served until it is
  (cache kept 243 of 400 credentials)          <- was 52 of 400
  PASS: an evicting cache never answers with another credential's SIDs
  PASS: a borrowed set survives a resolve started from its own callback
  All credential SID resolver tests passed!
(identical output from the Release build)

sudo <build>/Debug/src/vfs/tests/vfs_acl_sid_enforce_test -> 4/4 PASS
sudo <build>/Debug/src/vfs/tests/vfs_identity_test        -> 13/13 PASS
sudo <build>/Debug/src/vfs/tests/vfs_acl_test             -> all PASS

sudo ctest --test-dir <build>/Debug   --output-on-failure       -> 100%, 55/55
sudo ctest --test-dir <build>/Release --output-on-failure -j 8  -> 100%, 55/55
sudo ctest --test-dir <build>/Debug -C extended -L vfs --output-on-failure
                                                                      -> 100%, 27/27
```

### uncrustify (`--replace` twice, then an explicit `--check` per file)

```
PASS: src/vfs/vfs_open_cache.h (41907 bytes)
PASS: src/vfs/nfs/nfs3_open_state.h (6816 bytes)
PASS: src/vfs/vfs_cred_sids.c (23005 bytes)
PASS: src/vfs/vfs_cred_sids.h (5162 bytes)
PASS: src/vfs/tests/vfs_cred_sids_test.c (26524 bytes)
PASS: src/server/nfs/nfs_common.h (40949 bytes)
PASS: src/server/smb/smb_session.h (27816 bytes)
PASS: src/server/smb/smb_internal.h (170559 bytes)
PASS: src/server/smb/smb_proc_session_setup.c (48175 bytes)
```

No FAIL lines. ASCII check over every added line in the branch diff: clean.
(`src/server/nfs/nfs_common.h` carries pre-existing non-ASCII section signs at
lines 131, 157, 163, 202 and 890, none of them touched by this wave.)

## Open items / concerns

1. `chimera_vfs_cred_hash()` still walks `cred->gids[]` with the unclamped
   `ngids` (`src/vfs/vfs_cred.c:55-57`). Read-only, pre-existing, shared with
   the open-handle cache; not fixed here.
2. The suggested `hash ^ (hash >> 32)` fold for Important 4 measurably does not
   work (see the table above); a full avalanche was used instead.
3. Nothing pushed, no PR opened.
