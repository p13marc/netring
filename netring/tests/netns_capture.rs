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
    // setns even into our own namespace needs CAP_SYS_ADMIN, so skip where we
    // do not have it. The guard has to be the *outcome*, not `geteuid() == 0`:
    // in a rootless container (podman's default, which is what the CI
    // integration runner is) the process is uid 0 inside its user namespace
    // while CAP_SYS_ADMIN over the host netns is absent — euid says "root",
    // setns says EPERM, and a uid guard walks straight into the panic. That is
    // what kept the `Integration/test-integration` lane red.
    //
    // Reproduce the shape without a container:
    //   unshare -Ur --map-root-user <this test binary> run_in_current_namespace
    let ns = NetNs::current().unwrap();
    match ns.run_in(|| 21 * 2) {
        Ok(out) => assert_eq!(out, 42),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping run_in assertion: setns needs CAP_SYS_ADMIN ({e})");
        }
        Err(e) => panic!("run_in failed for a reason other than privilege: {e}"),
    }
}
