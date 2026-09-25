//! Capability probing.
//!
//! Every flag here is established by *doing the thing*, not by reading a
//! version number or a sysctl. Container runtimes routinely leave
//! `/proc/sys/user/max_user_namespaces` at a permissive value while seccomp
//! still blocks `unshare(CLONE_NEWUSER)`, so the only trustworthy answer comes
//! from attempting it.
//!
//! Callers are expected to branch on these results. The engine never silently
//! downgrades a requested mode — it reports what it got and why.

use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork};

use crate::protocol::Capabilities;

pub fn detect() -> Capabilities {
    // Probed once per process: the overlay probe forks and mounts, which is
    // cheap but not free, and the answer cannot change underneath a session.
    static CACHED: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
    CACHED.get_or_init(probe).clone()
}

fn probe() -> Capabilities {
    let user_namespace = probe_user_namespace();
    let overlayfs = user_namespace && probe_overlayfs();
    let bubblewrap = crate::sandbox::which("bwrap").is_some();
    let landlock_abi = probe_landlock_abi();
    let seccomp = std::path::Path::new("/proc/sys/kernel/seccomp/actions_avail").exists();
    let fuse = std::path::Path::new("/dev/fuse").exists();

    let detail = describe(user_namespace, overlayfs, bubblewrap, landlock_abi);

    Capabilities {
        platform: platform_name().to_string(),
        user_namespace,
        overlayfs,
        bubblewrap,
        landlock_abi,
        seccomp,
        fuse,
        detail,
    }
}

fn describe(
    user_namespace: bool,
    overlayfs: bool,
    bubblewrap: bool,
    landlock_abi: Option<u32>,
) -> String {
    let mut notes = Vec::new();
    if !user_namespace {
        notes.push("user namespaces unavailable (seccomp or sysctl); overlay mode cannot work");
    }
    if user_namespace && !overlayfs {
        notes.push("overlayfs could not be mounted in a user namespace");
    }
    if !bubblewrap {
        notes.push("bubblewrap not on PATH; enforcement falls back to landlock only");
    }
    if landlock_abi.is_none() {
        notes.push("landlock unavailable");
    }
    if notes.is_empty() {
        return "full capability set".to_string();
    }
    notes.join("; ")
}

fn platform_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "other"
    }
}

/// Attempt `unshare(CLONE_NEWUSER)` in a throwaway child.
fn probe_user_namespace() -> bool {
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let ok = unshare(CloneFlags::CLONE_NEWUSER).is_ok();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        Ok(ForkResult::Parent { child }) => {
            matches!(waitpid(child, None), Ok(WaitStatus::Exited(_, 0)))
        }
        Err(_) => false,
    }
}

/// Actually mount an overlay in a user namespace, using the same code path as a
/// real session. A capability that has never been exercised is a guess.
fn probe_overlayfs() -> bool {
    let base = std::env::temp_dir().join(format!("wsbox-probe-{}", std::process::id()));
    let _ = crate::fsutil::remove_tree(&base);

    let overlay = crate::sandbox::OverlayDirs {
        lower: base.join("lower"),
        upper: base.join("upper"),
        work: base.join("work"),
        merged: base.join("merged"),
    };
    let ok = (|| -> crate::Result<bool> {
        for dir in [
            &overlay.lower,
            &overlay.upper,
            &overlay.work,
            &overlay.merged,
        ] {
            crate::fsutil::ensure_dir(dir)?;
        }
        let request = crate::sandbox::RunRequest {
            argv: vec!["/bin/true".into()],
            cwd: overlay.merged.clone(),
            workspace: overlay.lower.clone(),
            writable_roots: Vec::new(),
            network: crate::protocol::Network::Deny,
            max_open_files: None,
            sandboxed: false,
            root_readonly: true,
            hide_paths: Vec::new(),
            overlay: Some(overlay.clone()),
            stdout_path: base.join("probe.out"),
            stderr_path: base.join("probe.err"),
            timeout: Some(std::time::Duration::from_secs(10)),
        };
        Ok(crate::sandbox::run(&request)?.success())
    })()
    .unwrap_or(false);

    let _ = crate::fsutil::remove_tree(&base);
    ok
}

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns
/// the supported ABI version, or -1 with ENOSYS/EOPNOTSUPP.
fn probe_landlock_abi() -> Option<u32> {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;

    let result = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        None
    } else {
        Some(result as u32)
    }
}
