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

Not yet:

- long-lived daemon (`wsboxd`) and streaming stdout
- fanotify/FUSE for full write fidelity (intermediate states within one call are
  not visible — only the end state)
- landlock/seccomp enforcement layered on top of the mount isolation
