//! Network-namespace handle + `run_in` (issue #126).
//!
//! The handle basics run unprivileged; `run_in` (which calls `setns`) needs
//! `CAP_SYS_ADMIN` and skips gracefully otherwise.

use netring::netns::NetNs;

#[test]
fn current_namespace_handle_basics() {
    let ns = NetNs::current().expect("open /proc/self/ns/net");
    assert_eq!(ns.label(), "current");
    let ino = ns.inode().expect("fstat ns fd");
    assert!(ino > 0, "namespace inode should be non-zero");

    let clone = ns.try_clone().expect("dup ns fd");
    assert_eq!(clone.label(), "current");
    assert_eq!(
        clone.inode().unwrap(),
        ino,
        "clone names the same namespace"
    );
}

#[test]
fn from_pid_self_matches_current() {
    let by_pid = NetNs::from_pid(std::process::id()).expect("open /proc/<pid>/ns/net");
    let current = NetNs::current().unwrap();
    assert_eq!(
        by_pid.inode().unwrap(),
        current.inode().unwrap(),
        "our pid's netns is our current netns"
    );
}

#[test]
fn run_in_current_namespace() {
    // setns even into our own namespace needs CAP_SYS_ADMIN — skip otherwise.
    if !is_root() {
        eprintln!("skipping run_in test: not root (setns needs CAP_SYS_ADMIN)");
        return;
    }
    let ns = NetNs::current().unwrap();
    let out = ns
        .run_in(|| 21 * 2)
        .expect("run_in should enter our own netns and run the closure");
    assert_eq!(out, 42);
}

fn is_root() -> bool {
    // SAFETY: geteuid is always safe.
    unsafe { libc::geteuid() == 0 }
}
