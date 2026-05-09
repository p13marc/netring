//! Built-in redirect-all XDP program.
//!
//! Hand-written 5-instruction `bpf_redirect_map(&xsks_map,
//! ctx->rx_queue_index, XDP_PASS)` program. Pre-compiled to BPF ELF
//! bytecode and vendored in `programs/redirect_all.bpf.o`. See
//! `programs/README.md` for regeneration instructions.

use aya::Ebpf;

use crate::error::Error;

use super::{LoaderError, XdpProgram};

/// The vendored compiled program. Regenerate via `xdp-tools/`.
const REDIRECT_ALL_BYTECODE: &[u8] = include_bytes!("programs/redirect_all.bpf.o");

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
