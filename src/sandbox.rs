//! Sandbox execution.
//!
//! Two things happen here that cannot be done from a managed runtime:
//!
//!  1. **User namespace + overlayfs.** bubblewrap on its own cannot mount
//!     overlayfs — it drops its capabilities, and the mount fails with
//!     `cannot mount overlay read-only`. So the overlay is mounted *before*
//!     bubblewrap starts, by a forked child that first unshares
//!     `CLONE_NEWUSER | CLONE_NEWNS` and has its uid/gid maps written by the
//!     parent.
//!  2. **Exec with a bounded lifetime.** The command runs in its own process
//!     group, output goes to files (never through the protocol channel), and a
//!     timeout tears the whole thing down.
//!
//! The overlay mount is what makes the guarantee real: the real workspace is
//! the read-only *lower* layer, every write lands in `upper/`, and the sandbox
//! only ever sees the merged view. A command that truncates a file cannot
//! destroy it — the original is still in the lower layer.

use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};

use crate::error::{Error, Result};
use crate::protocol::Network;

/// Exit status used by the child when sandbox *setup* fails, so the parent can
/// tell "the sandbox could not start" apart from "the command failed".
const SETUP_FAILED: i32 = 125;

/// Where the overlay lives. All four directories must be on the same
/// filesystem — overlayfs rejects a tmpfs upper over an ext4 lower.
#[derive(Debug, Clone)]
pub struct OverlayDirs {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub merged: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub workspace: PathBuf,
    pub writable_roots: Vec<PathBuf>,
    pub network: Network,
    pub max_open_files: Option<u64>,
    /// Wrap in bubblewrap. When false the command runs directly (still with
    /// output capture and timeout).
    pub sandboxed: bool,
    /// Root filesystem read-only. Only meaningful when `sandboxed`.
    pub root_readonly: bool,
    /// Paths masked with an empty tmpfs inside the sandbox — the ledger
    /// directory lives here. Without this the agent could delete its own
    /// audit trail.
    pub hide_paths: Vec<PathBuf>,
    pub overlay: Option<OverlayDirs>,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct Outcome {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
}

impl Outcome {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && self.signal.is_none() && !self.timed_out
    }
}

pub fn run(request: &RunRequest) -> Result<Outcome> {
    if let Some(overlay) = &request.overlay {
        for dir in [&overlay.upper, &overlay.work, &overlay.merged] {
            crate::fsutil::ensure_dir(dir)?;
        }
    }

    let plan = Plan::build(request)?;

    let stdout_file = std::fs::File::create(&request.stdout_path)
        .map_err(|error| Error::io(&request.stdout_path, error))?;
    let stderr_file = std::fs::File::create(&request.stderr_path)
        .map_err(|error| Error::io(&request.stderr_path, error))?;

    let stdout_fd = std::os::fd::AsRawFd::as_raw_fd(&stdout_file);
    let stderr_fd = std::os::fd::AsRawFd::as_raw_fd(&stderr_file);
    // Opened here, not in the child: `File::open` allocates.
    let devnull_fd = std::fs::File::open("/dev/null")
        .map(std::os::fd::IntoRawFd::into_raw_fd)
        .unwrap_or(-1);

    // Child -> parent: "I have unshared, write my uid/gid maps".
    let mut ready: [RawFd; 2] = [0; 2];
    // Parent -> child: "maps are written, carry on".
    let mut go: [RawFd; 2] = [0; 2];
    if unsafe { libc::pipe(ready.as_mut_ptr()) } != 0 {
        return Err(Error::IoBare(std::io::Error::last_os_error()));
    }
    if unsafe { libc::pipe(go.as_mut_ptr()) } != 0 {
        return Err(Error::IoBare(std::io::Error::last_os_error()));
    }

    let needs_userns = plan.needs_userns;
    let started = Instant::now();

    // SAFETY: everything the child touches was built before the fork. After
    // `fork()` the child issues raw syscalls only — no allocation, no locking —
    // because the parent may be multi-threaded (a library consumer, or a test
    // harness), and a lock held by another thread would be copied as held.
    match unsafe { fork() }.map_err(|error| Error::Sandbox(format!("fork failed: {error}")))? {
        ForkResult::Child => child(&plan, stdout_fd, stderr_fd, devnull_fd, ready, go),
        ForkResult::Parent { child } => {
            unsafe {
                libc::close(ready[1]);
                libc::close(go[0]);
            }

            if needs_userns {
                if let Err(error) = write_maps(child, ready[0], go[1]) {
                    unsafe {
                        libc::close(ready[0]);
                        libc::close(go[1]);
                    }
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    return Err(error);
                }
            }
            unsafe {
                libc::close(ready[0]);
                libc::close(go[1]);
            }

            let (status, timed_out) = wait_with_timeout(child, request.timeout)?;
            let duration_ms = started.elapsed().as_millis() as u64;

            let (exit_code, signal) = match status {
                WaitStatus::Exited(_, code) => (code, None),
                WaitStatus::Signaled(_, signal, _) => (128 + signal as i32, Some(signal as i32)),
                _ => (128, None),
            };

            if exit_code == SETUP_FAILED {
                return Err(Error::Sandbox(format!(
                    "sandbox setup failed; see {}",
                    request.stderr_path.display()
                )));
            }

            Ok(Outcome {
                exit_code,
                signal,
                timed_out,
                duration_ms,
            })
        }
    }
}

/// Everything the forked child needs, prepared before `fork()`.
///
/// The child must not allocate. `fork()` in a multi-threaded parent copies
/// whatever locks the other threads held, and the allocator takes locks — so a
/// `format!` in the child can deadlock. All `CString`s, the argv pointer array
/// and the mount options are therefore built here, in the parent, and the child
/// only issues raw syscalls.
struct Plan {
    /// Owns the buffers that `argv_ptrs` points into. Dropping this would leave
    /// the pointer array dangling, so it must outlive the child. Never read
    /// directly — it exists purely to keep the pointers valid.
    #[allow(dead_code)]
    argv: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    cwd: CString,
    mount: Option<MountPlan>,
    needs_userns: bool,
    max_open_files: Option<u64>,
}

struct MountPlan {
    source: CString,
    target: CString,
    fstype: CString,
    data: CString,
}

impl Plan {
    fn build(request: &RunRequest) -> Result<Self> {
        let argv_strings = if request.sandboxed {
            build_bwrap_argv(request)?
        } else {
            request.argv.clone()
        };
        if argv_strings.is_empty() {
            return Err(Error::Invalid("empty argv".into()));
        }

        let mut argv: Vec<CString> = Vec::with_capacity(argv_strings.len());
        for arg in &argv_strings {
            argv.push(
                CString::new(arg.as_str()).map_err(|_| {
                    Error::Invalid(format!("argument contains a NUL byte: {arg:?}"))
                })?,
            );
        }
        // Pointers into `argv`'s heap buffer, which does not move afterwards.
        let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        let cwd = CString::new(request.cwd.as_os_str().as_encoded_bytes())
            .map_err(|_| Error::Invalid("cwd contains a NUL byte".into()))?;

        let mount = match &request.overlay {
            Some(overlay) => {
                let data = format!(
                    "lowerdir={},upperdir={},workdir={}",
                    overlay.lower.display(),
                    overlay.upper.display(),
                    overlay.work.display()
                );
                let source = CString::new("overlay")
                    .map_err(|_| Error::Invalid("bad overlay source".into()))?;
                Some(MountPlan {
                    fstype: source.clone(),
                    source,
                    target: CString::new(overlay.merged.as_os_str().as_encoded_bytes())
                        .map_err(|_| Error::Invalid("bad overlay target".into()))?,
                    data: CString::new(data)
                        .map_err(|_| Error::Invalid("bad overlay options".into()))?,
                })
            }
            None => None,
        };

        Ok(Self {
            argv,
            argv_ptrs,
            cwd,
            mount,
            needs_userns: request.overlay.is_some(),
            max_open_files: request.max_open_files,
        })
    }
}

/// The forked child. Raw syscalls only — see [`Plan`].
fn child(
    plan: &Plan,
    stdout_fd: RawFd,
    stderr_fd: RawFd,
    devnull_fd: RawFd,
    ready: [RawFd; 2],
    go: [RawFd; 2],
) -> ! {
    unsafe {
        libc::close(ready[0]);
        libc::close(go[1]);

        // stdin from /dev/null: agent commands must never block on a prompt.
        if devnull_fd >= 0 {
            libc::dup2(devnull_fd, libc::STDIN_FILENO);
        }
        libc::dup2(stdout_fd, libc::STDOUT_FILENO);
        libc::dup2(stderr_fd, libc::STDERR_FILENO);
        libc::setpgid(0, 0);

        if plan.needs_userns {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                fail(b"unshare(CLONE_NEWUSER|CLONE_NEWNS) failed", last_errno());
            }
            // Hand control to the parent so it can write uid_map/gid_map.
            if libc::write(ready[1], b"R".as_ptr().cast(), 1) != 1 {
                libc::_exit(SETUP_FAILED);
            }
            libc::close(ready[1]);

            let mut byte = [0u8; 1];
            if libc::read(go[0], byte.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(SETUP_FAILED);
            }
            libc::close(go[0]);

            if let Some(mount) = &plan.mount
                && libc::mount(
                    mount.source.as_ptr(),
                    mount.target.as_ptr(),
                    mount.fstype.as_ptr(),
                    0,
                    mount.data.as_ptr().cast(),
                ) != 0
            {
                fail(b"mount overlayfs failed", last_errno());
            }
        } else {
            libc::close(ready[1]);
            libc::close(go[0]);
        }

        if let Some(limit) = plan.max_open_files {
            let rlimit = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit);
        }

        libc::chdir(plan.cwd.as_ptr());
        libc::execvp(plan.argv_ptrs[0], plan.argv_ptrs.as_ptr());
        fail(b"execvp failed", last_errno());
    }
}

fn last_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Write a diagnostic to stderr and exit with [`SETUP_FAILED`].
///
/// Stack-only, deliberately: this runs in a forked child.
fn fail(message: &[u8], errno: i32) -> ! {
    let mut buffer = [0u8; 192];
    let mut len = 0usize;
    len += append(&mut buffer[len..], b"wsbox: sandbox setup failed: ");
    len += append(&mut buffer[len..], message);
    len += append(&mut buffer[len..], b" (errno ");
    len += append_i32(&mut buffer[len..], errno);
    len += append(&mut buffer[len..], b")\n");
    unsafe {
        libc::write(libc::STDERR_FILENO, buffer.as_ptr().cast(), len);
        libc::_exit(SETUP_FAILED);
    }
}

fn append(buffer: &mut [u8], bytes: &[u8]) -> usize {
    let count = bytes.len().min(buffer.len());
    buffer[..count].copy_from_slice(&bytes[..count]);
    count
}

fn append_i32(buffer: &mut [u8], value: i32) -> usize {
    if value == 0 {
        return append(buffer, b"0");
    }
    let negative = value < 0;
    let mut digits = [0u8; 12];
    let mut count = 0usize;
    let mut remaining = value.unsigned_abs();
    while remaining > 0 && count < digits.len() {
        digits[count] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        count += 1;
    }
    let mut written = 0usize;
    if negative && written < buffer.len() {
        buffer[written] = b'-';
        written += 1;
    }
    while count > 0 {
        count -= 1;
        if written >= buffer.len() {
            break;
        }
        buffer[written] = digits[count];
        written += 1;
    }
    written
}

/// Parent side of the uid/gid map handshake.
fn write_maps(child: Pid, ready_fd: RawFd, go_fd: RawFd) -> Result<()> {
    let mut byte = [0u8; 1];
    let read = unsafe { libc::read(ready_fd, byte.as_mut_ptr().cast(), 1) };
    if read != 1 {
        return Err(Error::Sandbox(
            "child failed before requesting uid/gid maps".into(),
        ));
    }

    let pid = child.as_raw();
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // `setgroups` must be denied before an unprivileged gid_map can be written.
    // Older kernels may not expose the file at all; that is not fatal.
    let _ = std::fs::write(format!("/proc/{pid}/setgroups"), "deny");
    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1"))
        .map_err(|error| Error::Sandbox(format!("uid_map: {error}")))?;
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1"))
        .map_err(|error| Error::Sandbox(format!("gid_map: {error}")))?;

    let wrote = unsafe { libc::write(go_fd, b"G".as_ptr().cast(), 1) };
    if wrote != 1 {
        return Err(Error::Sandbox("failed to release child".into()));
    }
    Ok(())
}

fn wait_with_timeout(child: Pid, timeout: Option<Duration>) -> Result<(WaitStatus, bool)> {
    let Some(timeout) = timeout else {
        let status = waitpid(child, None).map_err(|error| Error::Sandbox(error.to_string()))?;
        return Ok((status, false));
    };

    let deadline = Instant::now() + timeout;
    loop {
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {}
            Ok(status) => return Ok((status, false)),
            Err(error) => return Err(Error::Sandbox(error.to_string())),
        }
        if Instant::now() >= deadline {
            // The child called setsid via bubblewrap's `--new-session`, so its
            // process group id equals its pid; `--die-with-parent` takes care
            // of the sandboxed grandchildren.
            let _ = killpg(child, Signal::SIGKILL);
            let _ = kill(child, Signal::SIGKILL);
            let status = waitpid(child, None).map_err(|error| Error::Sandbox(error.to_string()))?;
            return Ok((status, true));
        }
        std::thread::sleep(Duration::from_millis(15));
    }
}

/// Build the bubblewrap invocation.
///
/// Ordering is load-bearing:
///   1. the overlay bind must happen **before** the ledger directory is masked,
///      otherwise the bind source no longer exists;
///   2. masking must happen after every bind, or the agent can reach the
///      `upper/` directory and the content-addressed store directly.
fn build_bwrap_argv(request: &RunRequest) -> Result<Vec<String>> {
    let bwrap = which("bwrap").ok_or_else(|| {
        Error::Unsupported("bubblewrap (bwrap) not found on PATH; overlay mode requires it".into())
    })?;

    let mut argv = vec![bwrap, "--die-with-parent".to_string()];

    if request.root_readonly {
        argv.push("--ro-bind".into());
    } else {
        argv.push("--bind".into());
    }
    argv.push("/".into());
    argv.push("/".into());

    argv.extend(["--dev".into(), "/dev".into()]);
    argv.extend(["--proc".into(), "/proc".into()]);

    // A private /tmp keeps calls from leaking state through it — but only when
    // shadowing /tmp does not hide something the sandbox still has to reach.
    // bubblewrap resolves bind *sources* in its own namespace, so a workspace
    // living under /tmp would become unreachable the moment /tmp is replaced.
    let mut needed: Vec<&Path> = vec![&request.workspace, &request.cwd];
    needed.extend(request.writable_roots.iter().map(PathBuf::as_path));
    needed.extend(request.hide_paths.iter().map(PathBuf::as_path));
    if let Some(overlay) = &request.overlay {
        needed.push(overlay.merged.as_path());
    }
    if !would_shadow(Path::new("/tmp"), &needed) {
        argv.extend(["--tmpfs".into(), "/tmp".into()]);
    }

    // Workspace: the overlay's merged view when we have one, otherwise the real
    // tree bound read-write.
    //
    // The bind is emitted even when the workspace is read-only. `--tmpfs /tmp`
    // above already replaced the host's `/tmp` with an empty tmpfs, so a
    // workspace that happens to live under `/tmp` would otherwise vanish from
    // the sandbox entirely.
    let workspace_writable = request
        .writable_roots
        .iter()
        .any(|root| paths_overlap(root, &request.workspace));

    if workspace_writable {
        match &request.overlay {
            Some(overlay) => {
                argv.push("--bind".into());
                argv.push(overlay.merged.display().to_string());
                argv.push(request.workspace.display().to_string());
            }
            None => {
                argv.push("--bind".into());
                argv.push(request.workspace.display().to_string());
                argv.push(request.workspace.display().to_string());
            }
        }
    } else {
        argv.push("--ro-bind".into());
        argv.push(request.workspace.display().to_string());
        argv.push(request.workspace.display().to_string());
    }

    for root in &request.writable_roots {
        if paths_overlap(root, &request.workspace) {
            continue;
        }
        argv.push("--bind".into());
        argv.push(root.display().to_string());
        argv.push(root.display().to_string());
    }

    // Mask the ledger only after every bind has been set up.
    //
    // The mask is emitted unconditionally, even for a path that does not exist
    // yet: bubblewrap creates the destination, and skipping the mask would
    // silently leave the audit trail reachable from inside the sandbox.
    for hidden in &request.hide_paths {
        argv.push("--tmpfs".into());
        argv.push(hidden.display().to_string());
    }

    argv.push("--chdir".into());
    argv.push(request.cwd.display().to_string());
    argv.push("--unshare-pid".into());
    argv.push("--new-session".into());
    if request.network == Network::Deny {
        argv.push("--unshare-net".into());
    }
    argv.push("--".into());
    argv.extend(request.argv.iter().cloned());
    Ok(argv)
}

/// True when one path is the other, or one contains the other.
fn paths_overlap(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

/// True when shadowing `dir` with a fresh tmpfs would hide any of `needed`.
fn would_shadow(dir: &Path, needed: &[&Path]) -> bool {
    needed.iter().any(|path| path.starts_with(dir))
}

pub fn which(program: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Network;

    fn base_request() -> RunRequest {
        RunRequest {
            argv: vec!["echo".into(), "hi".into()],
            cwd: PathBuf::from("/work"),
            workspace: PathBuf::from("/work"),
            writable_roots: vec![PathBuf::from("/work")],
            network: Network::Deny,
            max_open_files: None,
            sandboxed: true,
            root_readonly: true,
            hide_paths: vec![PathBuf::from("/home/u/.local/share/wsbox")],
            overlay: None,
            stdout_path: PathBuf::from("/tmp/out"),
            stderr_path: PathBuf::from("/tmp/err"),
            timeout: None,
        }
    }

    #[test]
    fn overlay_bind_precedes_ledger_mask() {
        let mut request = base_request();
        request.overlay = Some(OverlayDirs {
            lower: "/work".into(),
            upper: "/ledger/upper".into(),
            work: "/ledger/work".into(),
            merged: "/ledger/merged".into(),
        });
        let argv = build_bwrap_argv(&request).unwrap();

        let bind_at = argv
            .windows(3)
            .position(|window| window[0] == "--bind" && window[1] == "/ledger/merged")
            .expect("merged bind present");
        let mask_at = argv
            .windows(2)
            .position(|window| window[0] == "--tmpfs" && window[1].contains("wsbox"))
            .expect("ledger mask present");

        assert!(
            bind_at < mask_at,
            "the overlay bind must be set up before the ledger directory is masked"
        );
    }

    #[test]
    fn read_only_workspace_gets_a_read_only_bind() {
        let mut request = base_request();
        request.writable_roots.clear();
        let argv = build_bwrap_argv(&request).unwrap();

        // It must still be bound — `--tmpfs /tmp` would otherwise hide a
        // workspace that lives under /tmp — but read-only.
        assert!(
            argv.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == "/work" && w[2] == "/work"),
            "a read-only workspace must be re-exposed after the /tmp tmpfs"
        );
        assert!(
            !argv.windows(2).any(|w| w[0] == "--bind" && w[1] == "/work"),
            "a read-only workspace must not get a writable bind"
        );
    }

    #[test]
    fn network_deny_adds_netns() {
        let argv = build_bwrap_argv(&base_request()).unwrap();
        assert!(argv.contains(&"--unshare-net".to_string()));
    }
}
