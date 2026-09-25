# wsbox protocol v1

One JSON object per line in each direction (NDJSON). `stdout` carries the
protocol only; diagnostics go to `stderr`. A client that spawns the engine can
therefore treat stdout as a pure channel.

## Compatibility

- `protocol` is a **major** version. A mismatch is a hard error; the engine never
  guesses what an older or newer caller meant.
- Unknown fields are ignored, so minor additions are forward compatible.
- An unknown `method` returns `unsupported` — never a panic.

## Envelope

```jsonc
{
  "protocol": 1,
  "method": "exec",
  "params": { /* method-specific */ },
  "id": "anything"        // echoed back; optional
}
```

## Response

```jsonc
{
  "protocol": 1,
  "ok": true,
  "result": { /* method-specific */ },
  "id": "anything"
}
```

```jsonc
{
  "protocol": 1,
  "ok": false,
  "error": { "code": "sandbox", "message": "..." }
}
```

Error codes: `io`, `json`, `unsupported`, `invalid_request`, `session_not_found`,
`session_exists`, `sandbox`, `conflict`, `protocol_version`, `spawn`.

---

## `capabilities`

No parameters.

```jsonc
{
  "platform": "linux",
  "userNamespace": true,
  "overlayfs": true,
  "bubblewrap": true,
  "landlockAbi": 10,
  "seccomp": true,
  "fuse": true,
  "detail": "full capability set"
}
```

Every flag is established by *doing the thing*. Container runtimes routinely
leave `/proc/sys/user/max_user_namespaces` permissive while seccomp still blocks
`unshare(CLONE_NEWUSER)`, so `userNamespace` and `overlayfs` come from actually
attempting the call in a throwaway child.

---

## `session.open`

```jsonc
{
  "session": "sess_7f3a",
  "workspace": "/home/u/proj",
  "ledgerDir": "/home/u/.local/share/wsbox",   // optional
  "mode": "auto",                               // auto | overlay | snapshot
  "copyMode": "auto"                            // snapshot only: auto | full
}
```

```jsonc
{
  "session": "sess_7f3a",
  "workspace": "/home/u/proj",
  "ledgerDir": "/home/u/.local/share/wsbox",
  "mode": "overlay",
  "capabilities": { /* as above */ },
  "degraded": null
}
```

`degraded` is non-null when the requested mode could not be honoured, e.g.
`"overlay mode unavailable, degraded to snapshot: user namespaces unavailable"`.
**Callers must check it.** Requesting `overlay` explicitly on a host that cannot
provide it fails with `unsupported` rather than degrading.

---

## `exec`

```jsonc
{
  "session": "sess_7f3a",
  "ledgerDir": "/home/u/.local/share/wsbox",
  "call": "call_42",
  "cwd": "/home/u/proj",
  "argv": ["bash", "-lc", "python3 -c ..."],
  "spec": {
    "enabled": true,
    "backend": "auto",              // auto | bubblewrap | landlock | none
    "writableRoots": ["/home/u/proj"],
    "passthrough": ["/home/u/proj/target"],
    "network": "deny",              // deny | allow
    "maxOpenFiles": 4096
  },
  "timeoutMs": 120000,
  "maxOutputBytes": 65536
}
```

`argv` travels in the body rather than on the command line, so large commands and
shell fragments never hit `ARG_MAX`.

`spec` is deliberately neutral: the engine knows about paths and network, not
about `read-only` / `workspace-write` / `approve-all`. Mapping a tier onto this
is the caller's job — that is what lets several agents share one engine.

An empty `writableRoots` makes the workspace read-only for the call.

### `passthrough`

Absolute paths **inside the workspace** that are bound straight from the real
filesystem, winning over the overlay. For derived output: `target/`,
`node_modules/`, `.venv/`.

The command still runs against the merged view, so it reads the agent's edits; it
writes those subtrees to the real disk, so build artefacts never enter `upper/`
and never reach the CAS.

Two invariants are enforced, because a caller that gets them wrong would quietly
disable the whole mechanism:

- the path must be inside the workspace — passthrough cannot widen the sandbox;
- the path must not be (or contain) `.git` — history must stay journaled.

Writes there are **not journaled and not reversible**. The declaration is
recorded per call in the ledger, so the audit record is explicit about which
calls had an unwatched subtree.

### Result

```jsonc
{
  "call": "call_42",
  "exitCode": 0,
  "signal": null,
  "timedOut": false,
  "durationMs": 812,
  "changes": [
    {
      "path": "app.py",
      "op": "modify",                 // add | modify | delete | chmod
      "beforeBytes": 5180,
      "afterBytes": 0,
      "beforeSha": "971329793905...",
      "afterSha": "e3b0c44298fc...",
      "diff": "--- a/app.py\n+++ /dev/null\n@@ -1,400 +0,0 @@\n-...",
      "diffTruncated": false,
      "suspicious": true,
      "reason": "file shrank 100% (5180 -> 0 bytes)",
      "reversible": true
    }
  ],
  "stdout": "",
  "stderr": "",
  "stdoutBytes": 0,
  "stderrBytes": 0,
  "stdoutSpill": null,
  "stderrSpill": null,
  "ledgerRef": "sess_7f3a#0",
  "warnings": []
}
```

- `diff` is `null` for binary content and when the baseline could not be read
  (a `warnings` entry says so).
- `diff` describes the **end state** of the call: a file written and then
  restored before the command exits produces no change. Intermediate writes
  within one call are not currently observable.
- `path` is a workspace-relative **key**, not necessarily the file's name. When
  the name is valid UTF-8 and does not start with `!hex:`, the key is the name
  itself. Otherwise the key is `!hex:` followed by the hex of the name's raw
  bytes — Unix filenames are byte strings, and a lossy conversion would map two
  distinct names onto U+FFFD and merge them into one entry. The encoding is
  injective: a file literally named `!hex:...` is escaped too. Use
  `wsbox::fsutil::{encode_key, decode_key}` to convert; `restore --path` and the
  ledger query filters accept either the key or a plain relative path.
- `diffTruncated` marks a diff clipped to 64 KiB. The full text is always in the
  CAS, keyed by `beforeSha` / `afterSha`.
- `suspicious` means the file lost at least 80% of its content and was at least
  1 KiB before. **The engine only reports it — deciding what to do is the
  caller's job.**
- Output beyond `maxOutputBytes` is replaced with head+tail plus a pointer to the
  full capture in `calls/<id>/`.

---

## `changes`

```jsonc
{ "session": "sess_7f3a", "ledgerDir": "..." }
```

Returns the accumulated change set for the whole session, in the same `Change`
shape. Restored paths drop out.

---

## `apply`

```jsonc
{ "session": "sess_7f3a", "ledgerDir": "...", "force": false }
```

```jsonc
{
  "session": "sess_7f3a",
  "ok": false,
  "applied": [],
  "conflicts": ["app.py"]
}
```

Every path is verified against its baseline before anything is written: a file
the user edited mid-session aborts the **whole** apply rather than being silently
clobbered. `force: true` skips the check.

In `snapshot` mode the workspace already holds the changes, so `apply` is a no-op
that reports success.

---

## `restore`

```jsonc
{ "session": "sess_7f3a", "ledgerDir": "...", "path": "app.py" }
{ "session": "sess_7f3a", "ledgerDir": "...", "all": true }
```

```jsonc
{ "session": "sess_7f3a", "restored": ["app.py"] }
```

Rewrites `upper/` in overlay mode (the real workspace was never touched) and the
workspace itself in snapshot mode.

---

## `session.discard`

Drops the session record. In snapshot mode it restores the baseline first, since
the workspace really was written. In overlay mode dropping the record is enough.

```jsonc
{ "session": "sess_7f3a", "reverted": [] }
```

---

## `ledger.query`

The audit surface. The ledger records *what happened*; the CAS holds *what the
bytes were*. Keeping those separate is what lets retention prune content without
making the audit trail lie.

```jsonc
{
  "session": "sess_7f3a",
  "ledgerDir": "...",
  "call": "call_42",          // optional: only this tool-call id
  "path": "src/main.rs",      // optional: only entries touching this path
  "sinceSeq": 10,             // optional: seq >= this
  "limit": 50                 // optional: newest-first cap
}
```

```jsonc
{
  "session": "sess_7f3a",
  "entries": [ /* LedgerEntry, newest first */ ],
  "total": 120,               // matching entries, before `limit`
  "ledgerEntries": 4000,      // entries in the whole ledger
  "head": "d1640421ba2f..."
}
```

---

## `history`

Every state a path passed through, derived from the ledger rather than from a
separate version store. A pruned blob still appears, flagged
`available: false` — the history never silently loses an entry.

```jsonc
{ "session": "sess_7f3a", "path": "src/main.rs" }
```

```jsonc
{
  "session": "sess_7f3a",
  "path": "src/main.rs",
  "baselineSha": "d768026d20a9...",
  "baselineAvailable": true,
  "versions": [
    {
      "seq": 0, "call": "call_42", "atMs": 1758800000000, "op": "modify",
      "beforeSha": "d768026d20a9...", "beforeBytes": 5180, "beforeAvailable": true,
      "afterSha": "82b2658fd589...", "afterBytes": 0, "afterAvailable": false
    }
  ]
}
```

---

## `gc`

Prunes intermediate content versions. Retention is deliberately asymmetric:

- the **baseline** of every touched path is never evicted — restoring the
  pre-session state must always work, and its size is bounded by the set of
  touched files rather than by the number of calls;
- the **current** state is never evicted — that is what `apply` writes;
- intermediates keep the most recent `keep` per path (default 5).

The ledger is not touched. `dryRun` reports what would go without deleting.

```jsonc
{ "session": "sess_7f3a", "keep": 5, "dryRun": false }
```

```jsonc
{
  "session": "sess_7f3a",
  "dryRun": false,
  "kept": 7,
  "pruned": 26,
  "prunedBytes": 6900000,
  "affected": ["big.txt"]
}
```

---

## `status`

Storage and activity summary, including the counterfactual that makes the
retention question concrete.

```jsonc
{
  "session": "sess_7f3a",
  "workspace": "/home/u/proj",
  "mode": "overlay",
  "changedPaths": 2,
  "ledgerEntries": 31,
  "ledgerBytes": 19422,
  "calls": 31,
  "casBlobs": 33,
  "casBytes": 8300010,
  "workspaceBytes": 200007,
  "naiveSnapshotBytes": 6200217
}
```

`naiveSnapshotBytes` is `workspaceBytes * calls`. Compare it against `casBytes` —
and note that for a single large file rewritten with distinct content every call,
the CAS is the more expensive of the two until `gc` runs.

---

## `ledger.verify`

Walks the hash chain in `ledger.jsonl`.

```jsonc
{ "session": "sess_7f3a", "entries": 12, "head": "d1640421ba2f..." }
```

Fails with `invalid_request` if any entry has been modified.
