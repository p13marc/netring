//! Classic BPF (cBPF) filter program types.
//!
//! [`BpfFilter`] holds a kernel-validated cBPF program. Construct
//! one of two ways:
//!
//! - **Recommended**: [`BpfFilter::builder()`] returns a typed
//!   [`BpfFilterBuilder`](crate::config::BpfFilterBuilder) covering
//!   ~90 % of common filter expressions (TCP/UDP/ICMP, host, port,
//!   net, VLAN, AND/OR/NOT) without external tools.
//! - **Escape hatch**: [`BpfFilter::new(Vec<BpfInsn>)`] takes raw
//!   instructions for filters outside the builder's vocabulary.
//!   Generate them with `tcpdump -dd "<expression>"` and paste in,
//!   or hand-roll. Validates the kernel
//!   [`MAX_INSNS`](BpfFilter::MAX_INSNS) limit.
//!
//! For eBPF socket filters (different opcodes, different verifier),
//! use [`aya`](https://crates.io/crates/aya) and attach to the
//! socket fd via `AsFd`.

/// A single classic BPF instruction.
///
/// Identical memory layout to `libc::sock_filter` so that
/// `&[BpfInsn]` can be passed directly to
/// `setsockopt(SO_ATTACH_FILTER)` via the existing conversion
/// (no runtime allocation, just a `from_raw_parts` cast).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    /// Instruction opcode.
    pub code: u16,
    /// Jump-if-true offset (relative to next instruction).
    pub jt: u8,
    /// Jump-if-false offset (relative to next instruction).
    pub jf: u8,
    /// Generic constant — meaning depends on `code`.
    pub k: u32,
}

impl From<BpfInsn> for libc::sock_filter {
    fn from(insn: BpfInsn) -> Self {
        libc::sock_filter {
            code: insn.code,
            jt: insn.jt,
            jf: insn.jf,
            k: insn.k,
        }
    }
}

impl From<libc::sock_filter> for BpfInsn {
    fn from(sf: libc::sock_filter) -> Self {
        Self {
            code: sf.code,
            jt: sf.jt,
            jf: sf.jf,
            k: sf.k,
        }
    }
}

/// A classic BPF filter program.
///
/// Constructed via [`BpfFilter::builder()`] (recommended) or
/// [`BpfFilter::new`] (escape hatch). See module docs.
#[derive(Debug, Clone)]
pub struct BpfFilter {
    instructions: Vec<BpfInsn>,
}

impl BpfFilter {
    /// Maximum instruction count enforced by the Linux kernel
    /// (`BPF_MAXINSNS` in `<linux/bpf_common.h>`). Filters larger
    /// than this are rejected at `setsockopt(SO_ATTACH_FILTER)`
    /// time; we surface the limit at construction instead.
    pub const MAX_INSNS: usize = 4096;

    /// Construct from raw instructions.
    ///
    /// Validates that `instructions.len() <= MAX_INSNS`. Use this
    /// for filters outside the typed builder's vocabulary —
    /// hand-rolled bytecode or output from `tcpdump -dd`.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::TooManyInstructions`] if the program
    /// exceeds `MAX_INSNS`.
    pub fn new(instructions: Vec<BpfInsn>) -> Result<Self, BuildError> {
        if instructions.len() > Self::MAX_INSNS {
            return Err(BuildError::TooManyInstructions {
                count: instructions.len(),
            });
        }
        Ok(Self { instructions })
    }

    /// Typed-builder entry point. See
    /// [`BpfFilterBuilder`](crate::config::BpfFilterBuilder).
    pub fn builder() -> super::bpf_builder::BpfFilterBuilder {
        super::bpf_builder::BpfFilterBuilder::new()
    }

    /// The instruction slice.
    pub fn instructions(&self) -> &[BpfInsn] {
        &self.instructions
    }

    /// Number of instructions.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Whether the filter has no instructions.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

/// Errors produced by [`BpfFilter::new`] and the typed builder.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// Two fragments selected mutually-exclusive protocols
    /// (e.g. `tcp().udp()` without OR composition between them).
    #[error("conflicting fragments: {a} and {b} can't both match the same packet")]
    ConflictingProtocols {
        /// Name of the first conflicting fragment.
        a: &'static str,
        /// Name of the second conflicting fragment.
        b: &'static str,
    },

    /// Filter exceeds the kernel's `BPF_MAXINSNS` limit.
    #[error(
        "filter exceeds {} instructions (kernel BPF_MAXINSNS limit), got {count}",
        BpfFilter::MAX_INSNS
    )]
    TooManyInstructions {
        /// The over-large instruction count.
        count: usize,
    },

    /// Port number outside the valid u16 range — only possible if
    /// the builder is fed via a runtime-typed interface; the
    /// chained `port: u16` API can't trigger this.
    #[error("port out of range: {0}")]
    PortOutOfRange(u32),

    /// IP prefix length larger than the address family permits.
    #[error("invalid IP prefix length: {0} (max 32 for IPv4, 128 for IPv6)")]
    InvalidPrefix(u8),

    /// IPv6 traffic with extension headers is currently
    /// unsupported by the typed builder. Use [`BpfFilter::new`]
    /// with hand-rolled instructions for these flows.
    #[error("ipv6 + extension headers not supported by the typed builder")]
    Ipv6ExtHeader,

    /// `or()` was called with a closure that produced no fragments.
    #[error("OR of zero branches")]
    EmptyOr,

    /// Forward jump distance exceeds the 8-bit relative offset
    /// representable in `BpfInsn::jt` / `jf`. Realistically only
    /// reachable with very wide OR chains.
    #[error("forward jump distance too large for cBPF (>255 instructions)")]
    JumpTooFar,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_insn_matches_sock_filter() {
        assert_eq!(
            std::mem::size_of::<BpfInsn>(),
            std::mem::size_of::<libc::sock_filter>()
        );
    }

    #[test]
    fn bpf_insn_roundtrip() {
        let insn = BpfInsn {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 12,
        };
        let sf: libc::sock_filter = insn.into();
        let back: BpfInsn = sf.into();
        assert_eq!(insn, back);
    }

    #[test]
    fn bpf_filter_accessors() {
        let insns = vec![
            BpfInsn {
                code: 0x28,
                jt: 0,
                jf: 0,
                k: 12,
            },
            BpfInsn {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0xFFFF,
            },
        ];
        let filter = BpfFilter::new(insns.clone()).unwrap();
        assert_eq!(filter.len(), 2);
        assert!(!filter.is_empty());
        assert_eq!(filter.instructions(), &insns);
    }

    #[test]
    fn bpf_filter_rejects_oversize() {
        let oversize = vec![
            BpfInsn {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0xFFFF,
            };
            BpfFilter::MAX_INSNS + 1
        ];
        let err = BpfFilter::new(oversize).unwrap_err();
        assert!(matches!(err, BuildError::TooManyInstructions { count } if count == BpfFilter::MAX_INSNS + 1));
    }
}
