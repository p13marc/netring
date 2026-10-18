//! AF_PACKET backend implementation.

pub(crate) mod ffi;

pub(crate) mod fanout;
pub(crate) mod filter;
pub(crate) mod ring;
pub mod rx;
pub(crate) mod socket;
pub mod tx;

use crate::error::Error;

/// Validate frame_size constraints shared by RX and TX builders.
pub(crate) fn validate_frame_size(frame_size: usize) -> Result<(), Error> {
    if !frame_size.is_multiple_of(ffi::TPACKET_ALIGNMENT) {
        return Err(Error::Config(format!(
            "frame_size {} is not a multiple of TPACKET_ALIGNMENT ({})",
            frame_size,
            ffi::TPACKET_ALIGNMENT
        )));
    }
    if frame_size < ffi::TPACKET3_HDRLEN {
        return Err(Error::Config(format!(
            "frame_size {} is less than TPACKET3_HDRLEN ({})",
            frame_size,
            ffi::TPACKET3_HDRLEN
        )));
    }
    Ok(())
}

/// `(major, minor)` of a kernel release string (`"6.12.107+deb13-…"`).
fn parse_kernel_release(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// The running kernel's `(major, minor)`, from `uname(2)`; `None` if it
/// can't be read.
fn kernel_version() -> Option<(u32, u32)> {
    static VERSION: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();
    *VERSION.get_or_init(|| {
        // SAFETY: `uname` fills the zeroed struct we own.
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } != 0 {
            return None;
        }
        // SAFETY: the kernel NUL-terminates `release`.
        let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
        parse_kernel_release(&release.to_string_lossy())
    })
}

/// Whether VLAN re-insertion can run on a kernel of `version`: it marks a
/// rewritten packet in `hv1.tp_padding`, which TPACKET_V3 zeroes per
/// packet only since Linux 3.14 (`prb_fill_vlan_info`) — on an older
/// kernel a stale marker from the slot's previous packet would skip the
/// re-insertion (and the kernel reports no TPID there). Unknown: assume
/// a current kernel.
fn vlan_reinsert_supported_on(version: Option<(u32, u32)>) -> bool {
    version.is_none_or(|v| v >= (3, 14))
}

/// [`vlan_reinsert_supported_on`] the running kernel.
pub(crate) fn vlan_reinsert_supported() -> bool {
    vlan_reinsert_supported_on(kernel_version())
}

#[cfg(test)]
mod kernel_tests {
    use super::*;

    #[test]
    fn kernel_release_strings_parse() {
        assert_eq!(
            parse_kernel_release("6.12.107+deb13-cloud-amd64"),
            Some((6, 12))
        );
        assert_eq!(parse_kernel_release("3.13.0-170-generic"), Some((3, 13)));
        assert_eq!(parse_kernel_release("4.4"), Some((4, 4)));
        assert_eq!(parse_kernel_release("garbage"), None);
        assert!(kernel_version().is_some(), "uname works here");
    }

    /// Review r1: re-insertion relies on a marker in `tp_padding`, zeroed
    /// per packet only since 3.14.
    #[test]
    fn vlan_reinsert_needs_3_14() {
        assert!(!vlan_reinsert_supported_on(Some((3, 13))));
        assert!(!vlan_reinsert_supported_on(Some((3, 2))));
        assert!(vlan_reinsert_supported_on(Some((3, 14))));
        assert!(vlan_reinsert_supported_on(Some((6, 12))));
        assert!(vlan_reinsert_supported_on(None));
    }
}
