//! XDP program loader for AF_XDP capture.
//!
//! Available with the `xdp-loader` Cargo feature.
//!
//! The standard AF_XDP recipe needs an XDP program loaded into the
//! kernel that calls `bpf_redirect_map(&xsks_map,
//! ctx->rx_queue_index, XDP_PASS)`. Without it, your AF_XDP socket
//! receives nothing — the socket is created but the kernel never
//! redirects traffic to it.
//!
//! This module provides:
//!
//! - [`XdpProgram`] — owns a loaded XDP program plus its embedded
//!   `BPF_MAP_TYPE_XSKMAP`. Construct via [`default_program`] for the
//!   built-in redirect-all program, or via custom aya integration in
//!   the future.
//! - [`XdpAttachment`] — RAII guard for the program's interface
//!   attachment. On drop, the program is detached.
//!
//! The simplest path is [`crate::XdpSocketBuilder::with_default_program`],
//! which orchestrates load + attach + register in one call.
//!
//! ```no_run
//! use netring::XdpSocket;
//!
//! # fn main() -> Result<(), netring::Error> {
//! let xsk = XdpSocket::builder()
//!     .interface("eth0")
//!     .queue_id(0)
//!     .with_default_program()
//!     .build()?;
//! // packets flow into xsk; on drop, program is detached.
//! # Ok(()) }
//! ```
//!
//! Aya (pure Rust) drives the actual `bpf(2)` and netlink calls.

mod default_program;
mod program;

pub use default_program::default_program;
pub use program::{XdpAttachment, XdpFlags, XdpProgram};

/// Returns `Err(ExclusiveBuilderOptions)` if both the built-in and a
/// caller-supplied XDP program were requested. Pulled out for unit
/// testability without constructing a real `XdpProgram`.
pub(crate) fn check_program_conflict(
    attach_default: bool,
    has_program: bool,
) -> Result<(), LoaderError> {
    if attach_default && has_program {
        Err(LoaderError::ExclusiveBuilderOptions)
    } else {
        Ok(())
    }
}

/// Errors specific to the XDP loader.
#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    /// Wrapper around any aya error.
    #[error("XDP loader (aya): {0}")]
    Aya(String),

    /// The compiled program object lacks the expected program symbol.
    #[error("vendored XDP program missing symbol `{0}`")]
    SymbolMissing(&'static str),

    /// The compiled program object lacks the expected map.
    #[error("vendored XDP program missing map `{0}`")]
    MapMissing(&'static str),

    /// Builder options that are mutually exclusive were both set.
    #[error("with_default_program() conflicts with with_program()")]
    ExclusiveBuilderOptions,
}

impl From<LoaderError> for crate::error::Error {
    fn from(e: LoaderError) -> Self {
        crate::error::Error::Loader(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vendored bytecode bytes (re-imported for the integrity test).
    const REDIRECT_ALL_BYTECODE: &[u8] = include_bytes!("programs/redirect_all.bpf.o");

    #[test]
    fn vendored_bytecode_is_elf_bpf() {
        // ELF magic.
        assert_eq!(&REDIRECT_ALL_BYTECODE[0..4], b"\x7fELF");
        // 64-bit, little-endian.
        assert_eq!(REDIRECT_ALL_BYTECODE[4], 2, "ELFCLASS64");
        assert_eq!(REDIRECT_ALL_BYTECODE[5], 1, "ELFDATA2LSB");
        // Machine type at offset 0x12 must be EM_BPF (0xf7) in LE.
        assert_eq!(
            u16::from_le_bytes([REDIRECT_ALL_BYTECODE[0x12], REDIRECT_ALL_BYTECODE[0x13]]),
            247,
            "EM_BPF"
        );
    }

    #[test]
    fn vendored_bytecode_has_expected_strings() {
        // The compiled object's `.strtab` contains the program and
        // map symbol names. Probe the bytes directly — this catches
        // accidental commits of the wrong file (e.g., a stale
        // placeholder) without requiring a BPF parser dep.
        let bytes = REDIRECT_ALL_BYTECODE;
        let mut found_prog = false;
        let mut found_map = false;
        let prog_name = b"xdp_sock_prog\0";
        let map_name = b"xsks_map\0";
        for window in bytes.windows(prog_name.len()) {
            if window == prog_name {
                found_prog = true;
                break;
            }
        }
        for window in bytes.windows(map_name.len()) {
            if window == map_name {
                found_map = true;
                break;
            }
        }
        assert!(found_prog, "vendored .bpf.o missing `xdp_sock_prog` symbol");
        assert!(found_map, "vendored .bpf.o missing `xsks_map` symbol");
    }

    #[test]
    fn xdp_flags_round_trip_via_aya() {
        let f = XdpFlags::DRV_MODE | XdpFlags::REPLACE;
        let aya = f.to_aya();
        // Sanity: flags carry through.
        assert!(aya.contains(aya::programs::XdpFlags::DRV_MODE));
        assert!(aya.contains(aya::programs::XdpFlags::REPLACE));
    }
}
