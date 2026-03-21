//! Tests for error conditions (no CAP_NET_RAW needed for some).

use netring::{Capture, Error};

#[test]
fn interface_not_found() {
    let err = Capture::new("nonexistent_iface_xyz_42").unwrap_err();
    match err {
        Error::InterfaceNotFound(name) => assert_eq!(name, "nonexistent_iface_xyz_42"),
        Error::PermissionDenied => {} // acceptable if no CAP_NET_RAW
        other => panic!("unexpected error: {other}"),
    }
}
