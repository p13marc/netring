//! eBPF socket filter integration via AsFd.
//!
//! This example demonstrates how to attach an eBPF program to a netring
//! capture socket using the `aya` crate. All netring handles implement
//! `AsFd`, enabling external eBPF attachment without raw file descriptors.
//!
//! **This example requires the `aya` crate** (not a netring dependency).
//! It is provided as documentation of the integration pattern.
//!
//! ```toml
//! [dependencies]
//! netring = "0.1"
//! aya = "0.13"
//! ```
//!
//! ## Usage Pattern
//!
//! ```rust,ignore
//! use aya::programs::SocketFilter;
//! use netring::Capture;
//! use std::os::fd::AsFd;
//!
//! // Load your compiled eBPF program
//! let mut bpf = aya::Ebpf::load_file("my_filter.o")?;
//! let prog: &mut SocketFilter = bpf.program_mut("my_filter")?.try_into()?;
//! prog.load()?;
//!
//! // Create a capture and attach the eBPF program via AsFd
//! let cap = Capture::new("eth0")?;
//! prog.attach(cap.as_fd())?;
//!
//! // Only packets passing the eBPF filter arrive
//! for pkt in cap.packets() {
//!     println!("{} bytes (filtered)", pkt.len());
//! }
//! ```

use std::os::fd::AsFd;

fn main() {
    // This example is documentation-only.
    // It demonstrates the AsFd integration pattern with aya.

    // Verify that Capture implements AsFd (compile-time check)
    fn _assert_as_fd<T: AsFd>() {}
    _assert_as_fd::<netring::Capture>();
    _assert_as_fd::<netring::AfPacketRx>();
    _assert_as_fd::<netring::Injector>();
    _assert_as_fd::<netring::AfPacketTx>();

    println!("All netring handles implement AsFd.");
    println!("See source code comments for aya integration pattern.");
}
