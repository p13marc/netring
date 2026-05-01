//! EINTR-safety: blocking syscalls under signal pressure.
//!
//! Verifies that Capture::next_batch_blocking returns Ok(None) on
//! timeout even when the polling thread receives a signal mid-syscall.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::{CaptureBuilder, PacketSource};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[test]
fn next_batch_blocking_survives_signal() {
    // Build the RX in the parent thread so capability errors propagate
    // before we spawn anything.
    let mut rx = CaptureBuilder::default()
        .interface(helpers::LOOPBACK)
        .block_timeout_ms(10)
        .build()
        .expect("build rx");

    // Background "signaler" — sends SIGUSR1 to the polling thread every
    // 50ms until the test asks it to stop. EINTR will land in the middle
    // of poll() at least once.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);

    // Capture the polling thread's pthread id once it's set.
    let target_tid = Arc::new(std::sync::Mutex::new(None));
    let target_tid_thread = Arc::clone(&target_tid);

    // Install a no-op handler for SIGUSR1 so the kernel doesn't kill us.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_sigusr1 as *const () as usize;
        // SA_RESTART would mask EINTR; we want it to surface.
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }

    let signaler = std::thread::spawn(move || {
        // Wait for the polling thread to publish its tid.
        let tid = loop {
            if stop_thread.load(Ordering::Relaxed) {
                return;
            }
            if let Some(t) = *target_tid_thread.lock().unwrap() {
                break t;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        while !stop_thread.load(Ordering::Relaxed) {
            unsafe {
                libc::pthread_kill(tid, libc::SIGUSR1);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    // Publish our tid so the signaler can target us.
    *target_tid.lock().unwrap() = Some(unsafe { libc::pthread_self() });

    // Run several next_batch_blocking calls; with the EINTR-safe wrapper,
    // each call should return Ok(_) regardless of how many times poll
    // gets interrupted.
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut ok_count = 0;
    while Instant::now() < deadline {
        match rx.next_batch_blocking(Duration::from_millis(50)) {
            Ok(_) => ok_count += 1,
            Err(e) => panic!("next_batch_blocking surfaced an error under EINTR: {e}"),
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = signaler.join();

    assert!(
        ok_count >= 5,
        "expected ≥5 successful poll cycles under signal pressure, got {ok_count}"
    );
}

extern "C" fn handle_sigusr1(_sig: libc::c_int) {
    // No-op; we only care that EINTR fires.
}
