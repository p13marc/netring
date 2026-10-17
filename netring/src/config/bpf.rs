//! Classic BPF (cBPF) filter program types.
//!
//! [`BpfFilter`] holds a kernel-validated cBPF program. Construct
//! one of two ways:
//!
//! - **Recommended**: [`BpfFilter::builder()`] returns a typed
//!   [`BpfFilterBuilder`](crate::config::BpfFilterBuilder) covering
//!   ~90 % of common filter expressions (TCP/UDP/ICMP, host, port,
//!   net, VLAN, AND/OR/NOT) without external tools.
//! - **Escape hatch**: [`BpfFilter::new`] takes raw
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
    /// Symbolic source captured during typed-builder compilation,
    /// powering [`to_human`](Self::to_human). `None` when the
    /// filter was constructed from raw bytecode via [`new`](Self::new).
    pub(crate) source: Option<super::bpf_builder::BpfFilterBuilder>,
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
    /// Returns [`BpfBuildError::TooManyInstructions`] if the program
    /// exceeds `MAX_INSNS`.
    pub fn new(instructions: Vec<BpfInsn>) -> Result<Self, BpfBuildError> {
        if instructions.len() > Self::MAX_INSNS {
            return Err(BpfBuildError::TooManyInstructions {
                count: instructions.len(),
            });
        }
        Ok(Self {
            instructions,
            source: None,
        })
    }

    /// Internal constructor used by the typed-builder compiler to
    /// attach a symbolic source for [`to_human`](Self::to_human).
    pub(crate) fn with_source(
        instructions: Vec<BpfInsn>,
        source: super::bpf_builder::BpfFilterBuilder,
    ) -> Result<Self, BpfBuildError> {
        if instructions.len() > Self::MAX_INSNS {
            return Err(BpfBuildError::TooManyInstructions {
                count: instructions.len(),
            });
        }
        Ok(Self {
            instructions,
            source: Some(source),
        })
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

    /// Consume the filter, returning its instruction vector.
    pub fn into_instructions(self) -> Vec<BpfInsn> {
        self.instructions
    }

    /// Number of instructions.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Whether the filter has no instructions.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// This filter with every accepted packet cut to at most `snap` bytes —
    /// a snap length enforced by the socket filter itself.
    ///
    /// A socket filter's return value is the number of bytes the kernel
    /// keeps (v6.12 net/packet/af_packet.c tpacket_rcv():
    /// `res = run_filter(skb, sk, snaplen); … if (snaplen > res) snaplen =
    /// res;`), which is the only per-packet capture length TPACKET_V3
    /// honours. The rewrite:
    ///
    /// - every `ret #k` with `k > 0` becomes `ret #min(k, snap)` (`ret #0`,
    ///   drop, is kept);
    /// - every `ret a` / `ret x` becomes a jump to a tail that returns
    ///   `min(a, snap)` / `min(x, snap)`:
    ///   `tail_x: txa; tail_a: jgt #snap, 0, 1; ret #snap; ret a`.
    ///
    /// The program grows by at most four instructions (only when it returns
    /// `a` or `x`); other jumps keep their targets. The symbolic source is
    /// kept, so [`to_human`](Self::to_human) renders the same expression.
    /// [`CaptureBuilder::snap_len`](crate::CaptureBuilder::snap_len) applies
    /// this to every filter a capture installs. A `snap` of `0` drops every
    /// packet.
    ///
    /// # Errors
    ///
    /// [`BpfBuildError::TooManyInstructions`] if the tail would take the
    /// program past [`MAX_INSNS`](Self::MAX_INSNS).
    pub fn with_snap_len(&self, snap: u32) -> Result<BpfFilter, BpfBuildError> {
        use super::bpf_compile::{
            BPF_JMP_JA, BPF_JMP_JGT_K, BPF_MISC_TXA, BPF_RET_A, BPF_RET_K, BPF_RET_X,
        };
        let insn = |code, jt, jf, k| BpfInsn { code, jt, jf, k };

        let n = self.instructions.len();
        let returns_x = self.instructions.iter().any(|i| i.code == BPF_RET_X);
        let returns_a = self.instructions.iter().any(|i| i.code == BPF_RET_A);
        // Tail layout after the original `n` instructions:
        //   [txa]                     only when some `ret x` exists
        //   jgt #snap, jt 0, jf 1     tail_a
        //   ret #snap
        //   ret a
        let tail_x = n;
        let tail_a = if returns_x { n + 1 } else { n };
        let tail_len = match (returns_a || returns_x, returns_x) {
            (false, _) => 0,
            (true, false) => 3,
            (true, true) => 4,
        };
        let total = n + tail_len;
        if total > Self::MAX_INSNS {
            return Err(BpfBuildError::TooManyInstructions { count: total });
        }

        let mut out = Vec::with_capacity(total);
        for (pc, i) in self.instructions.iter().enumerate() {
            // `ja` takes `k` as the offset from the next instruction.
            let ja_to = |target: usize| insn(BPF_JMP_JA, 0, 0, (target - (pc + 1)) as u32);
            out.push(match i.code {
                BPF_RET_K if i.k > 0 => insn(BPF_RET_K, 0, 0, i.k.min(snap)),
                BPF_RET_A => ja_to(tail_a),
                BPF_RET_X => ja_to(tail_x),
                _ => *i,
            });
        }
        if tail_len > 0 {
            if returns_x {
                out.push(insn(BPF_MISC_TXA, 0, 0, 0));
            }
            out.push(insn(BPF_JMP_JGT_K, 0, 1, snap));
            out.push(insn(BPF_RET_K, 0, 0, snap));
            out.push(insn(BPF_RET_A, 0, 0, 0));
        }
        Ok(Self {
            instructions: out,
            source: self.source.clone(),
        })
    }

    /// Render the filter as a canonical
    /// [`pcap-filter(7)`](https://www.tcpdump.org/manpages/pcap-filter.7.html)
    /// expression (e.g. `"tcp and dst port 443"`).
    ///
    /// Returns the empty string for filters built from the empty
    /// builder (matches every packet — pcap-filter syntax for
    /// "match all"). For filters constructed via
    /// [`new`](Self::new) with raw bytecode, returns
    /// `"<raw bytecode, N instructions>"` since the symbolic IR
    /// isn't available.
    ///
    /// The main chain and each [`or`](crate::config::BpfFilterBuilder::or)
    /// branch render as alternatives (`(tcp and dst port 80) or udp`),
    /// and [`negate`](crate::config::BpfFilterBuilder::negate) wraps the
    /// whole expression (`not (…)`).
    ///
    /// Best-effort: the output is guaranteed to be syntactically
    /// valid pcap-filter when constructed via the typed builder;
    /// no claim of byte-identical match with libpcap's
    /// `tcpdump -dd` bytecode output. Nor is it a promise of the same
    /// match set under libpcap: the rendering spells out the builder's
    /// chain, not the fragments the compiler implies. In particular a
    /// chain naming neither `.ipv4()` / `.ipv6()` nor an IPv6 address
    /// compiles IPv4-only, so `tcp and port 443` here means IPv4 TCP,
    /// whereas libpcap's `tcp` / `udp` / `port` also match IPv6 —
    /// prefix `ip and` for the libpcap equivalent.
    pub fn to_human(&self) -> String {
        self.to_string()
    }
}

impl std::fmt::Display for BpfFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(builder) => super::bpf_humanize::render(builder, f),
            None => write!(
                f,
                "<raw bytecode, {} instructions>",
                self.instructions.len()
            ),
        }
    }
}

/// Errors produced by [`BpfFilter::new`] and the typed builder.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BpfBuildError {
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

    /// An `or()` branch nested its own `or()` / `negate()`. The typed cBPF
    /// compiler only handles a flat OR of AND-chains (disjunctive normal
    /// form), so nested disjunction/negation inside a branch must be
    /// flattened by hand. For example, rewrite
    /// `a.or(|b| b.tcp().or(|c| c.udp()))` as
    /// `a.or(|b| b.tcp()).or(|c| c.udp())` — one OR level, three branches.
    /// (The runtime `.expr()` parser and the subscription `Predicate` AST do
    /// this normalization for you; only the hand-built `BpfFilterBuilder`
    /// chain hits this.)
    #[error(
        "nested or()/negate() inside an or() branch is not supported by the typed cBPF \
         compiler — flatten to a single OR of AND-chains, e.g. `a.or(b).or(c)` not \
         `a.or(|x| x.or(...))`"
    )]
    NestedOr,

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
                k: u32::MAX,
            },
        ];
        let filter = BpfFilter::new(insns.clone()).unwrap();
        assert_eq!(filter.len(), 2);
        assert!(!filter.is_empty());
        assert_eq!(filter.instructions(), &insns);
    }

    fn ins(code: u16, jt: u8, jf: u8, k: u32) -> BpfInsn {
        BpfInsn { code, jt, jf, k }
    }

    /// Ethernet + a 20-byte IPv4 header + 8 bytes of UDP, padded to 200.
    fn ipv4_frame() -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 186, 0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2, 0, 1, 0, 2, 0, 166, 0, 0]);
        f.resize(200, 0);
        f
    }

    #[test]
    fn with_snap_len_clamps_ret_k_keeps_ret_0() {
        // ldh [12]; jeq #0x800, 0, 1; ret #4294967295; ret #0
        let f = BpfFilter::new(vec![
            ins(0x28, 0, 0, 12),
            ins(0x15, 0, 1, 0x0800),
            ins(0x06, 0, 0, u32::MAX),
            ins(0x06, 0, 0, 0),
        ])
        .unwrap();
        let s = f.with_snap_len(96).unwrap();
        assert_eq!(s.len(), 4, "no tail without ret a / ret x");
        assert_eq!(s.instructions()[2], ins(0x06, 0, 0, 96));
        assert_eq!(s.instructions()[3], ins(0x06, 0, 0, 0), "drop stays drop");
        // A `ret #k` already below the snap length is unchanged.
        let small = BpfFilter::new(vec![ins(0x06, 0, 0, 40)]).unwrap();
        assert_eq!(
            small.with_snap_len(96).unwrap().instructions(),
            &[ins(0x06, 0, 0, 40)]
        );

        let frame = ipv4_frame();
        assert_eq!(f.verdict(&frame), u32::MAX);
        assert_eq!(s.verdict(&frame), 96);
        let mut arp = frame.clone();
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(s.verdict(&arp), 0);
    }

    #[test]
    fn with_snap_len_rewrites_ret_a_and_ret_x() {
        // `ldh [12]; ret a` returns the EtherType: 2048 for IPv4.
        let ret_a = BpfFilter::new(vec![ins(0x28, 0, 0, 12), ins(0x16, 0, 0, 0)]).unwrap();
        let frame = ipv4_frame();
        assert_eq!(ret_a.verdict(&frame), 2048);
        let clamped = ret_a.with_snap_len(100).unwrap();
        assert_eq!(clamped.verdict(&frame), 100);
        assert_eq!(clamped.len(), 2 + 3, "jgt; ret #snap; ret a");
        assert_eq!(
            clamped.instructions()[1],
            ins(0x05, 0, 0, 0),
            "ja to tail_a"
        );
        // A snap length above the returned value leaves it alone.
        assert_eq!(ret_a.with_snap_len(4096).unwrap().verdict(&frame), 2048);

        // `ldxb 4*([14]&0xf); ret x` returns the IPv4 header length (20);
        // `ret a` on another path still reaches tail_a past the txa.
        let both = BpfFilter::new(vec![
            ins(0x28, 0, 0, 12),     // 0: ldh [12]
            ins(0x15, 0, 2, 0x0800), // 1: jeq #0x800 → 2, else 4
            ins(0xb1, 0, 0, 14),     // 2: ldxb 4*([14]&0xf)
            ins(0x0e, 0, 0, 0),      // 3: ret x
            ins(0x16, 0, 0, 0),      // 4: ret a
        ])
        .unwrap();
        assert_eq!(both.verdict(&frame), 20);
        let mut arp = frame.clone();
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(both.verdict(&arp), 0x0806);
        let c = both.with_snap_len(10).unwrap();
        assert_eq!(c.len(), 5 + 4, "txa; jgt; ret #snap; ret a");
        assert_eq!(c.verdict(&frame), 10, "min(x, snap)");
        assert_eq!(c.verdict(&arp), 10, "min(a, snap)");
        let c = both.with_snap_len(5000).unwrap();
        assert_eq!(c.verdict(&frame), 20);
        assert_eq!(c.verdict(&arp), 0x0806);
    }

    #[test]
    fn with_snap_len_keeps_the_symbolic_source() {
        let f = BpfFilter::builder().udp().dst_port(53).build().unwrap();
        let s = f.with_snap_len(64).unwrap();
        assert_eq!(s.to_human(), f.to_human());
        assert_eq!(s.len(), f.len());
    }

    #[test]
    fn with_snap_len_overflow_is_an_error() {
        let mut insns = vec![ins(0x28, 0, 0, 12); BpfFilter::MAX_INSNS - 1];
        insns.push(ins(0x16, 0, 0, 0)); // ret a
        let f = BpfFilter::new(insns).unwrap();
        let err = f.with_snap_len(64).unwrap_err();
        assert!(
            matches!(err, BpfBuildError::TooManyInstructions { count } if count == BpfFilter::MAX_INSNS + 3),
            "{err:?}"
        );
        // Without `ret a` / `ret x` there is no tail: a full program still fits.
        let mut insns = vec![ins(0x28, 0, 0, 12); BpfFilter::MAX_INSNS - 1];
        insns.push(ins(0x06, 0, 0, u32::MAX));
        assert!(BpfFilter::new(insns).unwrap().with_snap_len(64).is_ok());
    }

    /// #222: the typed builder accepts the whole packet. `0xFFFF` cut every
    /// frame longer than 65535 bytes (lo's MTU makes 65549-byte frames).
    #[test]
    fn empty_builder_accepts_whole_packet() {
        let f = BpfFilter::builder().build().unwrap();
        assert_eq!(f.instructions(), &[ins(0x06, 0, 0, u32::MAX)]);
        assert_eq!(f.verdict(&ipv4_frame()), u32::MAX);
        let f = BpfFilter::builder().udp().build().unwrap();
        assert_eq!(f.verdict(&ipv4_frame()), u32::MAX);
    }

    #[test]
    fn bpf_filter_rejects_oversize() {
        let oversize = vec![
            BpfInsn {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: u32::MAX,
            };
            BpfFilter::MAX_INSNS + 1
        ];
        let err = BpfFilter::new(oversize).unwrap_err();
        assert!(
            matches!(err, BpfBuildError::TooManyInstructions { count } if count == BpfFilter::MAX_INSNS + 1)
        );
    }
}
