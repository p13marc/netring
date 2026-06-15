//! Built-in redirect-all XDP program.
//!
//! Hand-written 5-instruction `bpf_redirect_map(&xsks_map,
//! ctx->rx_queue_index, XDP_PASS)` program. Pre-compiled to BPF ELF
//! bytecode and vendored in `programs/redirect_all.bpf.o`. See
//! `programs/README.md` for regeneration instructions.
//!
//! **Alignment:** the bytecode is embedded with [`aya::include_bytes_aligned`],
//! **not** plain `include_bytes!`. aya-obj parses the ELF zero-copy via the
//! `object` crate, whose header reads require the data to be aligned; a plain
//! `include_bytes!` static has no alignment guarantee, so it loaded only in
//! builds where it happened to land aligned and failed ("error parsing ELF
//! data") in others — notably any build that also pulls `tokio` (i.e. every
//! Monitor build), where feature unification shifted the static to a misaligned
//! address. The aligned macro pins it regardless of feature graph.

use aya::Ebpf;

use crate::error::Error;

use super::{LoaderError, XdpProgram};

/// The vendored compiled program. Regenerate via `xdp-tools/`.
const REDIRECT_ALL_BYTECODE: &[u8] = aya::include_bytes_aligned!("programs/redirect_all.bpf.o");

/// Symbol name of the program inside the compiled object.
const PROGRAM_NAME: &str = "xdp_sock_prog";

/// Map name inside the compiled object.
const MAP_NAME: &str = "xsks_map";

/// Load the built-in redirect-all XDP program. The program contains
/// an embedded `BPF_MAP_TYPE_XSKMAP` named `xsks_map` of capacity
/// `max_queues`.
///
/// After this returns, call [`XdpProgram::attach`] to attach to an
/// interface, then [`XdpProgram::register`] (or its alias methods on
/// [`super::XdpAttachment`]) to register AF_XDP sockets on the map.
pub fn default_program(_max_queues: u32) -> Result<XdpProgram, Error> {
    // The BPF object's XSKMAP has its own `max_entries` baked in by
    // the compiler. `max_queues` is currently informational; we keep
    // the parameter to surface the kernel limit and to allow a future
    // resize via aya's `BTF_KIND_VAR` rewriting.
    let bpf = Ebpf::load(REDIRECT_ALL_BYTECODE).map_err(|e| LoaderError::Aya(e.to_string()))?;
    Ok(XdpProgram::new(bpf, PROGRAM_NAME, MAP_NAME))
}

/// The vendored table-driven filter+redirect program (0.25 W1a / S5).
/// Aligned for the same reason as [`REDIRECT_ALL_BYTECODE`].
const FILTER_REDIRECT_BYTECODE: &[u8] =
    aya::include_bytes_aligned!("programs/filter_redirect.bpf.o");

/// Program symbol inside `filter_redirect.bpf.o`.
const FILTER_PROGRAM_NAME: &str = "xdp_filter_prog";

/// Load the built-in **table-driven** filter+redirect XDP program (0.25 W1a).
///
/// Unlike [`default_program`] (which redirects every frame), this program reads
/// a `BPF_MAP_TYPE_HASH` named `filter_map` to decide, in-kernel, whether each
/// frame is interesting: a `{proto, port}` hit is redirected into the AF_XDP
/// socket; a miss is `XDP_PASS`ed up the normal stack. This is the kernel side
/// of the subscription union's early-shed — populate the map with
/// [`XdpProgram::set_filter`] (or [`super::XdpAttachment::set_filter`] after
/// attach) from the union's kernel-pushable `{proto, port}` atoms.
///
/// The returned program embeds the same `xsks_map` XSKMAP as the redirect-all
/// program, so [`XdpProgram::attach`] + [`XdpProgram::register`] work
/// identically. With an **empty** `filter_map`, the program redirects nothing
/// (everything is shed) — set at least one filter before expecting traffic.
pub fn filter_program() -> Result<XdpProgram, Error> {
    let bpf = Ebpf::load(FILTER_REDIRECT_BYTECODE).map_err(|e| LoaderError::Aya(e.to_string()))?;
    Ok(XdpProgram::new(bpf, FILTER_PROGRAM_NAME, MAP_NAME))
}
