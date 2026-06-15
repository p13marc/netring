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

pub use default_program::{default_program, filter_program};
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
    /// Table-driven filter+redirect program bytes (0.25 W1a).
    const FILTER_REDIRECT_BYTECODE: &[u8] = include_bytes!("programs/filter_redirect.bpf.o");

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
    fn filter_redirect_bytecode_is_elf_with_expected_symbols() {
        // ELF + EM_BPF, same shape check as redirect_all.
        assert_eq!(&FILTER_REDIRECT_BYTECODE[0..4], b"\x7fELF");
        assert_eq!(FILTER_REDIRECT_BYTECODE[4], 2, "ELFCLASS64");
        assert_eq!(FILTER_REDIRECT_BYTECODE[5], 1, "ELFDATA2LSB");
        assert_eq!(
            u16::from_le_bytes([
                FILTER_REDIRECT_BYTECODE[0x12],
                FILTER_REDIRECT_BYTECODE[0x13]
            ]),
            247,
            "EM_BPF"
        );
        // The program symbol + both maps must be present.
        for needle in [
            &b"xdp_filter_prog\0"[..],
            &b"xsks_map\0"[..],
            &b"filter_map\0"[..],
        ] {
            let found = FILTER_REDIRECT_BYTECODE
                .windows(needle.len())
                .any(|w| w == needle);
            assert!(
                found,
                "filter_redirect.bpf.o missing symbol {:?}",
                std::str::from_utf8(needle).unwrap()
            );
        }
    }

    #[test]
    fn vendored_programs_parse_under_aya() {
        // Both vendored objects must parse cleanly through aya's ELF/BTF loader
        // (the step that returns "error parsing ELF data" on a misaligned
        // `include_bytes!`). This is the regression guard for the alignment fix
        // — it runs in the default `cargo test` build, which pulls `tokio` and
        // so reproduces the feature-unification misalignment that plain
        // `include_bytes!` failed under. Loading stops at map creation (which
        // needs privileges); reaching that proves the parse succeeded.
        //
        // We assert the error, if any, is *not* a parse error: a privileged CI
        // runner gets `Ok`, an unprivileged one gets a map-creation `EPERM` —
        // both mean the ELF parsed.
        // Go through the production constructors so the test exercises the
        // *aligned* embedding in `default_program.rs` (not a test-local
        // `include_bytes!`, which would have no alignment guarantee).
        for (name, res) in [
            ("redirect_all", super::default_program(256)),
            ("filter_redirect", super::filter_program()),
        ] {
            if let Err(e) = res {
                let msg = e.to_string();
                assert!(
                    !msg.contains("parsing ELF") && !msg.contains("parsing BPF object"),
                    "{name}: aya failed to PARSE the vendored object \
                     (alignment regression?): {msg}"
                );
            }
        }
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
