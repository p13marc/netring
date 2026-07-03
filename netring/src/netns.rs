//! Linux network-namespace capture (issue #126).
//!
//! A [`NetNs`] is a handle to a network namespace (an open fd on a
//! `net` namespace file). [`NetNs::run_in`] runs a closure on a short-lived
//! scoped thread that has `setns(2)`'d into that namespace, so a socket created
//! inside the closure is bound to the target namespace's interfaces. Once
//! created, the socket fd is namespace-independent, so the built
//! [`Capture`](crate::Capture) is handed straight back to the caller and used
//! from any thread — including the tokio runtime, whose worker threads are never
//! themselves re-namespaced.
//!
//! ```no_run
//! use netring::netns::NetNs;
//! use netring::Capture;
//!
//! // Capture on `veth0` inside the `blue` namespace.
//! let ns = NetNs::from_name("blue")?;
//! let cap = Capture::builder().interface("veth0").netns(&ns)?;
//! # Ok::<(), netring::Error>(())
//! ```
//!
//! Requires `CAP_SYS_ADMIN` at runtime (for `setns`). AF_XDP capture in a
//! namespace is a documented follow-up; AF_PACKET is first-class here.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use nix::sched::{CloneFlags, setns};

/// A handle to a Linux network namespace (issue #126).
#[derive(Debug)]
pub struct NetNs {
    fd: OwnedFd,
    label: String,
}

impl NetNs {
    /// Open a namespace from an explicit `net` namespace path (e.g.
    /// `/proc/<pid>/ns/net` or `/run/netns/<name>`), tagged with `label` for
    /// diagnostics.
    pub fn from_path(path: impl AsRef<Path>, label: impl Into<String>) -> io::Result<Self> {
        let file = File::open(path.as_ref())?;
        Ok(Self {
            fd: OwnedFd::from(file),
            label: label.into(),
        })
    }

    /// Open a named namespace created by `ip netns add <name>` (i.e.
    /// `/run/netns/<name>`). The label is `name`.
    pub fn from_name(name: &str) -> io::Result<Self> {
        Self::from_path(format!("/run/netns/{name}"), name)
    }

    /// Open the namespace a process belongs to (`/proc/<pid>/ns/net`). The label
    /// is `pid:<pid>`.
    pub fn from_pid(pid: u32) -> io::Result<Self> {
        Self::from_path(format!("/proc/{pid}/ns/net"), format!("pid:{pid}"))
    }

    /// Open the caller's current namespace (`/proc/self/ns/net`).
    pub fn current() -> io::Result<Self> {
        Self::from_path("/proc/self/ns/net", "current")
    }

    /// The diagnostic label this handle was opened with.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The namespace's inode number (its stable kernel identity — two handles
    /// with the same inode name the same namespace).
    pub fn inode(&self) -> io::Result<u64> {
        use std::os::fd::AsRawFd;
        // SAFETY: `fstat` writes a fully-initialised `stat` for a valid fd; the
        // fd is owned by `self` and live for the call.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(self.fd.as_raw_fd(), &mut st) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st.st_ino as u64)
    }

    /// A borrowed view of the underlying namespace fd.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Duplicate the handle (a fresh fd on the same namespace).
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
            label: self.label.clone(),
        })
    }

    /// Run `f` on a scoped thread that has entered this namespace, returning its
    /// value. The thread exits immediately after, so no namespace restore is
    /// needed and the caller's own namespace is untouched. Sockets/fds created
    /// by `f` remain valid in the caller's threads afterwards.
    ///
    /// Errors from `setns(2)` (typically `EPERM` without `CAP_SYS_ADMIN`) are
    /// returned; a panic inside `f` is surfaced as an [`io::Error`].
    pub fn run_in<T, F>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> T + Send,
        T: Send,
    {
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| -> io::Result<T> {
                setns(self.fd.as_fd(), CloneFlags::CLONE_NEWNET)
                    .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
                Ok(f())
            });
            match handle.join() {
                Ok(res) => res,
                Err(_) => Err(io::Error::other("netns worker thread panicked")),
            }
        })
    }
}
