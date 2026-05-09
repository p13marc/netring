//! `XdpProgram` and `XdpAttachment` — RAII guards for a loaded
//! XDP program and its interface attachment.

use aya::Ebpf;
use aya::maps::xdp::XskMap;
use aya::programs::{Xdp, XdpFlags as AyaXdpFlags, links::FdLink};

use crate::afxdp::XdpSocket;
use crate::error::Error;

use super::LoaderError;

bitflags::bitflags! {
    /// Flags controlling how an XDP program attaches to an interface.
    /// Mirrors `IFLA_XDP_FLAGS` in the kernel.
    #[derive(Debug, Clone, Copy)]
    pub struct XdpFlags: u32 {
        /// Generic SKB-mode (works on every driver, slower).
        const SKB_MODE = 1 << 1;
        /// Native driver mode (preferred when the driver supports it).
        const DRV_MODE = 1 << 2;
        /// Hardware offload (Netronome SmartNIC etc.).
        const HW_MODE  = 1 << 3;
        /// Replace any existing program. Without this, attach fails
        /// with `EBUSY` if a program is already attached.
        const REPLACE  = 1 << 4;
    }
}

impl XdpFlags {
    /// Convert to aya's `XdpFlags`.
    pub(crate) fn to_aya(self) -> AyaXdpFlags {
        let mut out = AyaXdpFlags::default();
        if self.contains(XdpFlags::SKB_MODE) {
            out |= AyaXdpFlags::SKB_MODE;
        }
        if self.contains(XdpFlags::DRV_MODE) {
            out |= AyaXdpFlags::DRV_MODE;
        }
        if self.contains(XdpFlags::HW_MODE) {
            out |= AyaXdpFlags::HW_MODE;
        }
        if self.contains(XdpFlags::REPLACE) {
            out |= AyaXdpFlags::REPLACE;
        }
        out
    }
}

/// A loaded XDP program plus its embedded `BPF_MAP_TYPE_XSKMAP`.
///
/// Construct via [`super::default_program`]. The wrapped `Ebpf`
/// instance keeps both the program and the map alive.
pub struct XdpProgram {
    bpf: Ebpf,
    /// Name of the program inside the loaded object. Used to look up
    /// the program after the `Ebpf` has been moved.
    program_name: String,
    /// Name of the XSKMAP inside the loaded object.
    map_name: String,
}

impl XdpProgram {
    pub(crate) fn new(bpf: Ebpf, program_name: &str, map_name: &str) -> Self {
        Self {
            bpf,
            program_name: program_name.to_string(),
            map_name: map_name.to_string(),
        }
    }

    /// Wrap a caller-loaded `aya::Ebpf` for use with netring's XDP
    /// attach + register + RAII teardown.
    ///
    /// Use this when you've compiled your own XDP program (e.g. via
    /// `aya-bpf` and `bpf-linker`) and want netring to handle the
    /// kernel attach + AF_XDP socket registration. Your program
    /// must:
    ///
    /// 1. Define a `BPF_MAP_TYPE_XSKMAP` and use it in a
    ///    `bpf_redirect_map(&xsks_map, ctx->rx_queue_index, ...)`
    ///    call.
    /// 2. Be loaded by aya (`aya::Ebpf::load(...)`) before you call
    ///    this.
    ///
    /// `program_name` is the BPF program symbol name (the Rust
    /// `#[xdp(name = "...")]` or C `SEC("xdp")` function name).
    /// `map_name` is the XSKMAP's variable name in your source.
    ///
    /// ```no_run,ignore
    /// use aya::Ebpf;
    /// use netring::xdp::{XdpFlags, XdpProgram};
    ///
    /// let bpf = Ebpf::load(MY_BYTECODE)?;
    /// let mut prog = XdpProgram::from_aya(bpf, "my_xdp", "xsks_map");
    /// // build an XdpSocket as usual, then:
    /// prog.register(queue_id, &xsk)?;
    /// let _attachment = prog.attach("eth0", XdpFlags::DRV_MODE)?;
    /// ```
    pub fn from_aya(bpf: Ebpf, program_name: &str, map_name: &str) -> Self {
        Self::new(bpf, program_name, map_name)
    }

    /// Borrow the program's `XskMap` for setting/unsetting socket fds.
    pub fn xsk_map(&mut self) -> Result<XskMap<&mut aya::maps::MapData>, Error> {
        let map = self
            .bpf
            .map_mut(&self.map_name)
            .ok_or(LoaderError::MapMissing("xsks_map"))?;
        XskMap::try_from(map).map_err(|e| LoaderError::Aya(e.to_string()).into())
    }

    /// Register an AF_XDP socket on the program's XSKMAP at
    /// `queue_id`. Convenience wrapper around `xsk_map().set(...)`.
    pub fn register(&mut self, queue_id: u32, xsk: &XdpSocket) -> Result<(), Error> {
        use std::os::fd::AsRawFd;
        let mut map = self.xsk_map()?;
        let fd: i32 = xsk.as_raw_fd();
        map.set(queue_id, fd, 0)
            .map_err(|e| LoaderError::Aya(e.to_string()).into())
    }

    /// Attach the program to interface `iface` with the given mode.
    /// On Drop of the returned [`XdpAttachment`], the program is
    /// detached.
    pub fn attach(mut self, iface: &str, flags: XdpFlags) -> Result<XdpAttachment, Error> {
        let prog: &mut Xdp = self
            .bpf
            .program_mut(&self.program_name)
            .ok_or(LoaderError::SymbolMissing("xdp_sock_prog"))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| LoaderError::Aya(e.to_string()))?;
        prog.load().map_err(|e| LoaderError::Aya(e.to_string()))?;
        let link_id = prog
            .attach(iface, flags.to_aya())
            .map_err(|e| LoaderError::Aya(e.to_string()))?;
        // Take ownership of the link so we can detach in Drop.
        let xdp_link = prog
            .take_link(link_id)
            .map_err(|e| LoaderError::Aya(e.to_string()))?;
        let owned: FdLink = xdp_link
            .try_into()
            .map_err(|e: aya::programs::links::LinkError| LoaderError::Aya(e.to_string()))?;
        Ok(XdpAttachment {
            _link: owned,
            _program: self,
        })
    }
}

impl std::fmt::Debug for XdpProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpProgram")
            .field("program_name", &self.program_name)
            .field("map_name", &self.map_name)
            .finish()
    }
}

/// RAII guard for an attached XDP program. Drop detaches the program
/// from the interface; the program and map are then unloaded when
/// the inner `Ebpf` drops.
pub struct XdpAttachment {
    _link: FdLink,
    _program: XdpProgram,
}

impl XdpAttachment {
    /// Borrow the program's XSKMAP after attachment, e.g. to register
    /// additional sockets onto it.
    pub fn xsk_map(&mut self) -> Result<XskMap<&mut aya::maps::MapData>, Error> {
        self._program.xsk_map()
    }
}

impl std::fmt::Debug for XdpAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpAttachment")
            .field("program", &self._program)
            .finish()
    }
}
