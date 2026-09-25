# wsbox

**A workspace ledger sandbox for coding agents.** Every write a command makes is
observed, diffed and reversible — including the ones that bypass your edit tool.

```
$ wsbox exec --session s1 --call c1 -- bash -lc "python3 -c \"open('app.py','w').write('')\""

exit code 0

1 file(s) changed:
  modify  app.py  5180 -> 0 bytes  <== suspicious
      --- a/app.py
      +++ /dev/null
      @@ -1,400 +0,0 @@
      -def f0():
      -    return 0
      ...

warning: this call removed most of a file's content:
  app.py: file shrank 100% (5180 -> 0 bytes)
use `wsbox restore --session s1 --path app.py` if that was not intended.

# the real file is still 5180 bytes
```

## The problem

Agents bypass `edit` / `apply_patch` and rewrite files through `python`, `sed`,
`perl` or a build tool. When the anchoring is wrong the file loses content — and
if the change was never committed, the content is simply gone.

Isolation does not solve this. A sandbox that makes the workspace writable or
not writable says nothing about *what was written*. The gap is observability,
not enforcement.

## The approach

Three properties, in order of importance:

1. **The real workspace is never the first thing written.** Each session mounts
   an overlayfs view whose *lower* layer is the real workspace. Every write
   lands in `upper/`. `apply` is a separate, verified step.
2. **Content is durable before the change is reported.** The pre-call bytes of
   every changed path go into a content-addressed store before the diff is
   emitted, so no report can refer to content that cannot be recovered.
3. **The change set is the same regardless of which tool caused it.** The engine
   never parses `argv`; it diffs the filesystem. `python`, `sed`, a compiler and
   `apply_patch` all produce the same shape of result.

A 100% shrink of a file over 1 KiB is flagged `suspicious` — but **not blocked**.
Legitimate large rewrites exist, and a hard block just teaches the model to work
around it. The diff is put in front of the model instead, which is what lets it
notice and correct itself.

## Install

```bash
cargo build --release
install -Dm755 target/release/wsbox ~/.local/bin/wsbox
```

Requirements: Linux with unprivileged user namespaces and overlayfs (kernel
5.11+), plus `bubblewrap` on `PATH`.

## Quickstart

```bash
# What can this host actually do? Probed, not guessed.
wsbox capabilities

wsbox open --session demo --workspace ~/project

wsbox exec --session demo --call call-1 -- bash -lc "make -j4"

wsbox changes --session demo      # accumulated diff
wsbox apply   --session demo      # write it onto the real workspace
wsbox restore --session demo --path src/main.rs
wsbox discard --session demo
```

## Modes

| Mode | Real workspace written? | Requires |
|---|---|---|
| `overlay` | **No** — strong guarantee | unprivileged userns + overlayfs |
| `snapshot` | Yes, but every write is recoverable from the baseline copy | file read/write only |
| `auto` | picks the strongest available, reports what it got | — |

`session.open` returns the mode that actually took effect plus a `degraded`
reason when it could not honour the request. **The engine never silently
downgrades** — callers decide whether the weaker guarantee is acceptable.

## Security notes

- **The ledger directory is masked inside the sandbox.** Without this an agent
  could `rm -rf` its own audit trail. It is masked *after* the overlay bind,
  because bubblewrap resolves bind sources in its own namespace.
- **Root is read-only** (`--ro-bind / /`); only the workspace and explicitly
  listed writable roots are bound read-write.
- **Network is denied by default** via a private network namespace.
- **The sandbox child is a forked process that performs raw syscalls only.** No
  allocation, no locking — `fork()` in a multi-threaded parent copies whatever
  locks other threads held, and `format!` in that child can deadlock.
- **A workspace under `/tmp` disables the private `/tmp`.** bubblewrap resolves
  bind sources in its own mount namespace, so shadowing `/tmp` would make such a
  workspace unreachable. In that case `/tmp` stays read-only rather than being
  silently exposed read-write.

## Ledger

```
~/.local/share/wsbox/sessions/<id>/
  session.json      workspace, mode, copy stats
  upper/            every write the agent made (whiteouts are char device 0:0)
  work/  merged/    overlayfs working state
  base/             snapshot-mode baseline
  cas/<ab>/<sha>    content-addressed store of every baseline and result
  index.json        baseline vs current state per path
  calls/<id>/       captured stdout/stderr
  ledger.jsonl      append-only, hash-chained
```

`wsbox verify` walks the chain: a modified entry fails verification.

## Selective passthrough

Running `cargo build` inside the overlay would copy every artefact into `upper/`
— thousands of files, none of them interesting, all of them filling the content
store. The fix is to split by **path class**, not by tool:

```
/workspace               → overlay      (source: journaled, reversible)
/workspace/target        → real fs, rw  (derived: not journaled)
/workspace/node_modules  → real fs, rw
~/.cargo/registry        → real fs, rw
```

`cargo` still runs against the *merged* view, so it reads the code the model just
wrote. It writes `target/` straight to the real disk, so the build runs at native
speed, incremental caches survive between calls, and the change set stays clean.

```bash
wsbox exec --session s1 --call c1 --passthrough target -- cargo build
```

Two invariants make this safe to offer at all, and both are enforced:

- a passthrough path must be **inside the workspace**, so it cannot widen the
  sandbox's reach;
- it can never cover **`.git`**, so history cannot be rewritten through a path
  the journal does not watch.

Writes into a passthrough path are **not journaled and not reversible**. That is
the deliberate trade: the list is caller-declared, never chosen by the agent, and
the declaration itself is written into the ledger so the audit record says which
calls had an unwatched subtree.

> Splitting by *tool* instead — "cargo goes to the real workspace, python goes to
> the overlay" — does not work. Build scripts write source files, and a model can
> run `cargo` from `python`. Path class is the only stable boundary.

## Review component (experimental)

`wsbox` decides *where writes land*. It does not decide *whether they should be
kept* — that is `crates/wsbox-review`, an experimental component that answers one
question: **may this change set be applied without a person looking at it?**

```
permission gate    can this command run?         (unchanged, untouched)
wsbox sandbox      where do writes land?         (unchanged)
wsbox-review       should this change be kept?   <-- new
wsbox apply        write it to the workspace     (unchanged)
```

Those layers are orthogonal, so turning the review component on **changes no
existing approval behaviour** — it only answers "should the apply step ask?".
`Decision` has no "allow command" variant and `ChangeSetState` has no field for a
command, so an auto-approval cannot widen a permission boundary by construction.

```bash
wsbox-review --session s1 --task "change f to return 2"

needs review: `beyond_task` was not evaluated
  - `beyond_task` was not evaluated
  - `breaks_contract` was not evaluated
```

It is built around an `Assessor` seam rather than around a vendor:

```
Battery (versioned questions)
  └─ Assessor ──┬─ Rules    deterministic, free, offline, exact
                ├─ Jev      TypeSafe API, behind --features jev
                └─ Local    ← reserved for a small local model
       └─ Policy / Router   backend-independent
              └─ Decision
```

Two invariants make it fail closed, and both are enforced by the type system
rather than by remembering to check:

- **a missing answer is a reason to ask a human, never a reason to guess** — if
  the battery asked something the assessors could not answer, no auto-approval is
  possible;
- **`AutoApply` can only be produced by the router** — the variant lives in a
  private enum, so an expired API key, a rate limit, a timeout or a stale local
  model all land on `Review` by construction.

Deterministic hard rules are checked *before* any model and cannot be overridden:
a change to `.github/`, a lockfile, or a diff too large to review in full is held
whatever a model thinks of it. A model is a judgment layer, not a boundary.

The default mode is `RulesOnly`, which never auto-approves a real change — it
exercises the whole pipeline with the model slot empty, so the failure paths are
the ones that get tested. See [`docs/review.md`](docs/review.md).

### Shadow mode and the training corpus

The responsible way to switch a review model on is to measure it first, because
an auto-approval that is wrong is invisible until much later.

```bash
wsbox-review run --session s1 --call c2 --mode hosted --shadow --record --task "..."
wsbox-review resolve --session s1 --review 2 --outcome reject --note "emptied the function"
wsbox-review stats --session s1
```

```
reviews 4   resolved 4   with fallbacks 0

model said         applied  rejected  unresolved
auto_apply               1         0           0
review                   1         0           0
hold                     0         2           0

no dangerous auto-approvals in 4 resolved review(s).
```

`dangerousAutoApprove` — the model would have applied something a person
rejected — has to be zero before auto-approve is enabled.

The same records export to an auditable CSV, which is the corpus you would
train a local model on:

```bash
wsbox-review export --all --include-diffs --out corpus.csv
wsbox-review verify --input corpus.csv
```

Each row carries a digest chained to the previous one, so editing a cell breaks
the chain and `verify` names the row. Every row also points at the wsbox ledger
head it was taken under, so it traces back to the change set it describes.

The same records export in the shape a local decision model's fine-tuning loop
reads (`--format laya`), which is the point of collecting them — see
[`docs/laya.md`](docs/laya.md). The hosted model is what makes the corpus
possible; it is not the destination.

The schema keeps two kinds of label apart, because they are not
interchangeable:

- `q_*` columns are the **model's** per-question answers — dense, usable for
  distillation, but they carry the model's biases;
- `human_outcome` is the **person's** verdict — ground truth, but a *weak*
  label: it is a verdict on the change set, while the battery asks eight
  separate questions. Training the per-question heads on it directly is
  multiple-instance learning wearing a binary-classification hat.

Unanswered questions export as empty cells, not zeros: "not evaluated" and
"evaluated as zero" are different facts.

## Audit and retention

**The ledger and the content store have separate retention policies.** That
separation is the answer to "won't this grow forever?".

The ledger is the record of *what happened* — a few hundred bytes per call, so a
thousand calls cost a few hundred kilobytes. It is never pruned.

The CAS holds *what the bytes were*. It is pruned, and pruning only costs the
ability to re-materialise an old state, never the record that it existed:

```bash
wsbox query   --session s1 --path src/main.rs   # who touched it, when, with what argv
wsbox query   --session s1 --call call-42
wsbox history --session s1 --path src/main.rs   # every state, with availability
wsbox status  --session s1                      # storage, and the snapshot counterfactual
wsbox gc      --session s1 --keep 5 --dry-run
```

```
$ wsbox history --session s1 --path big.txt

history of big.txt

  baseline  d768026d20a9  available

  [0] modify  -> 82b2658fd589  c1   before:ok  after:pruned
  [1] modify  -> 72d063c0ac01  c2   before:pruned  after:pruned
  ...
  [29] modify -> 5f3ac1e9b204  c30  before:ok  after:ok
```

### What gc protects, unconditionally

| | |
|---|---|
| **Baseline** of every touched path | "restore what it looked like before the agent started" must always work. Its size is bounded by the set of touched files, not by the number of calls. |
| **Current** state | this is what `apply` writes |
| Last `keep` intermediates per path | default 5 |

### Why this does not grow like snapshotting

| | 50 calls on a 500 MB repo |
|---|---|
| full snapshot before every call | `500 MB × 50` = **25 GB** |
| overlay + CAS | only files actually written, deduplicated by digest |

Three filters do the work:

1. **overlayfs copies up only what is written.** Untouched files — `node_modules/`,
   `target/` — cost nothing at all.
2. **The CAS is content-addressed.** Identical bytes are stored once, and a
   rewrite that reproduces the same bytes produces *no diff at all*
   (`no_op_rewrite_produces_no_change` in the tests pins this).
3. **Only the baseline is unbounded-lifetime**, and it is bounded in size.

### The honest worst case

Deduplication does nothing when every version is unique. **One large file
rewritten with different content on every call is the worst case for content
addressing**, and in that case the CAS can exceed what whole-tree snapshots would
have cost:

```
$ wsbox status --session a1

workspace   200007 bytes of content
snapshot    6200217 bytes if the whole tree were copied before each call (cas is MORE EXPENSIVE)
```

That is what `gc` is for:

```
$ wsbox gc --session a1 --keep 3
{ "kept": 7, "pruned": 26, "prunedBytes": 6900000 }

$ wsbox status --session a1
cas         7 blobs, 1400010 bytes
snapshot    6200217 bytes if the whole tree were copied before each call (cas is cheaper)
```

For that workload the real fix is chunk-level storage (content-defined chunking,
as restic/borg do) so that only changed chunks are stored. Not implemented yet;
`gc` is the stopgap.

## Library use

The engine is also a library, and the wire protocol is the stable surface:

```rust
use wsbox::protocol::{Envelope, PROTOCOL_VERSION};

let response = wsbox::dispatch(&Envelope {
    protocol: PROTOCOL_VERSION,
    method: "exec".into(),
    params: serde_json::json!({ /* ... */ }),
    id: None,
});
```

See [`docs/protocol.md`](docs/protocol.md). The protocol is deliberately free of
agent-specific vocabulary — it takes a neutral spec (paths and network), not a
permission tier — so that different agents can share one engine while keeping
their own approval UX and change presentation.

## Testing

```bash
cargo test
```

The overlay tests need unprivileged user namespaces. Rather than passing
vacuously on a host that cannot provide them, they check the capability probe
and print a skip reason — a test that cannot fail is worse than no test.

## Status

Prototype. Working and covered by tests:

- overlay + snapshot modes, capability probing
- per-call diffs, delete/add/atomic-rename detection, suspicious-shrink flagging
- CAS, hash-chained ledger, `apply` / `restore` / `discard` with conflict detection
- audit surface: `query` / `history` / `status`, and `gc` with baseline-immortal retention
- selective passthrough for build output
- experimental review component (`crates/wsbox-review`), rules-only by default

Not yet:

- long-lived daemon (`wsboxd`) and streaming stdout
- fanotify/FUSE for full write fidelity (intermediate states within one call are
  not visible — only the end state)
- landlock/seccomp enforcement layered on top of the mount isolation
- chunk-level storage for the large-file-rewritten-repeatedly case
- automatic retention: `gc` is currently manual
- shadow mode: today the caller just ignores `may_auto_apply()`
- a local decision model has not been trained yet (see `docs/laya.md`)
