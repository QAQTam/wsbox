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

## `ledger.verify`

Walks the hash chain in `ledger.jsonl`.

```jsonc
{ "session": "sess_7f3a", "entries": 12, "head": "d1640421ba2f..." }
```

Fails with `invalid_request` if any entry has been modified.
