# Native SID enforcement -- development record

Design, decision and review record for the branch that makes an ACE carrying
only a native Windows SID enforce against the caller it names.

These are working documents, not user documentation. They are kept with the
code because the reasoning behind several non-obvious choices lives here and
nowhere else -- in particular why the resolution direction is inverted relative
to what was originally specified, and why the credential SID cache is shaped
the way it is.

## Contents

| File | What it holds |
| --- | --- |
| `plan.md` | The design and the task-by-task implementation plan, including the argument for resolving the caller rather than each ACE. |
| `ledger.md` | The execution record: every ruling made during implementation, every finding deferred rather than fixed, and the reasoning for each. |
| `reports/1.md` .. `reports/7.md` | Per-task implementation reports -- what changed, what was verified, and what each task's author flagged for review. |
| `reports/final-fixes.md` | The fixes applied after the whole-branch review. |

## The two things worth reading first

**The resolution direction is inverted relative to the original specification.**
The spec asked for each ACE's SID to be resolved to a uid/gid and the decoded
ACL rewritten. This branch resolves the *caller* once into the set of native
SIDs describing it, and compares ACE SIDs against that set. `plan.md` carries
the argument: the ACL belongs to the backend and is live in at least one
module, the gated-operation scratch area is far smaller than an ACL copy, and
the cost of the specified direction is worst for exactly the case the work
exists to serve. See "Deviation from the spec" in `plan.md`.

**This is the consumer half of a two-part change.** Nothing in the tree
currently constructs a `CHIMERA_PRINCIPAL_SID` principal -- the SMB descriptor
parser drops an ACE whose SID it cannot resolve rather than storing it
opaquely. The enforcement path is correct and covered by tests, but is reached
only from an out-of-tree backend that persists native SIDs, or from a future
in-tree producer. Anything written about this branch should say so plainly.

## Status

The branch carries its own tests (`src/vfs/tests/vfs_acl_sid_enforce_test.c`
covers the acceptance cases end to end over memfs, driven through the real
access gate). The quick test tier passes in both build configurations.
`ledger.md` records what was not run and what remains open, including several
deferred findings that are worth revisiting before this is proposed for merge.
