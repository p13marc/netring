//! tokio reactor registration on a private dup of a source's fd.
//!
//! tokio 1.53.3 deprecated the safe `AsyncFd::{new, with_interest}` as
//! unsound (tokio#8587): the fd an `AsyncFd` registers must stay open, and
//! keep referring to the same file description, for as long as the `AsyncFd`
//! lives. The adapters hand out `&mut` to their source (`get_mut`,
//! `ReadableGuard::get_inner_mut`), so a caller could swap the source out
//! from under a registration on its own fd. Registering a dup that only this
//! module can close makes the contract hold whatever happens to the source,
//! for the price of one extra fd per adapter.
//!
//! ## Liveness (#212)
//!
//! A registration also learns when its source died, so a wait — read or
//! write — ends instead of hanging. Two things make that necessary:
//!
//! - The kernel reports a socket error (`sk_err`) as `EPOLLERR`, which mio
//!   maps to error / write-closed readiness — never read readiness — and
//!   tokio hands `Ready::ERROR` only to a waiter whose interest includes
//!   `Interest::ERROR`. A read wait on a socket whose interface was
//!   removed (AF_PACKET: `ENETDOWN` from packet_notifier()) never woke.
//! - Some deaths raise no event at all: an AF_PACKET socket whose interface
//!   is deleted while already down (it is no longer running, so no second
//!   error), an AF_XDP socket whose device is unregistered (xsk_poll()
//!   reports nothing once the socket is unbound).
//!
//! - A TX socket raises nothing either: an AF_PACKET injector (protocol
//!   0) isn't running, so packet_notifier() sets no error, and frames
//!   queued but not kicked never complete once the device is gone (#225).
//!
//! So every registration includes `Interest::ERROR` and, while it waits,
//! watches for an error event and re-checks the source every
//! [`LIVENESS_PROBE`] of idle waiting. Either way the source's [`HealthFn`] decides: `Err` ends
//! the wait with that error, `Ok` (e.g. the interface is merely down) keeps
//! waiting. Under load the read readiness is set whenever the reader looks,
//! so neither check runs on the hot path.
//!
//! The probe's clock is a `timerfd` registered with the IO reactor
//! ([`ProbeTimer`]), not a tokio timer: a runtime built with only
//! `enable_io()` works. It is created on the first idle wait, so a reader
//! that never goes idle never opens it.

use std::future::Future;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::io::{Interest, Ready};

/// Is the source still usable? `Ok` — yes, possibly idle or down (keep
/// waiting); `Err` — it is gone, and the error ends the wait.
pub(crate) type HealthFn<T> = fn(&T) -> io::Result<()>;

/// A source's health verdict as the `io::Error` a wait reports: an
/// [`Error::Io`](crate::error::Error::Io) passes through as is (so the
/// adapter's `Error::Io` wrapping gives the caller back the same error).
pub(crate) fn health_io(res: crate::error::Result<()>) -> io::Result<()> {
    res.map_err(|e| match e {
        crate::error::Error::Io(e) => e,
        e => io::Error::other(e),
    })
}

/// How often an idle wait re-checks its source's health.
pub(crate) const LIVENESS_PROBE: Duration = Duration::from_secs(1);

/// Error events handled in one poll before yielding to the runtime. Each
/// needs a fresh epoll edge, so this only bounds a burst.
const ERROR_EVENTS_PER_POLL: usize = 4;

/// Resolves on the next error event (and clears it), or with the
/// registration's own error.
type ErrorWatch = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

/// Register a private dup of `fd` with the current tokio reactor.
///
/// Readiness is per file description, so the dup reports exactly what `fd`
/// would. Must be called in the context of a tokio runtime.
pub(crate) fn register_dup(fd: BorrowedFd<'_>, interest: Interest) -> io::Result<AsyncFd<OwnedFd>> {
    let dup = fd.try_clone_to_owned()?;
    // SAFETY: `dup` is an `OwnedFd` moved into the `AsyncFd`: it is open, its
    // `as_raw_fd()` never changes, and nothing but the `AsyncFd` (on drop or
    // `into_inner`) can close it.
    unsafe { AsyncFd::register_with_interest(dup, interest) }.map_err(io::Error::from)
}

/// A future resolving on the next error event on `fd`, which it clears.
fn watch_errors(fd: &Arc<AsyncFd<OwnedFd>>) -> ErrorWatch {
    let fd = Arc::clone(fd);
    Box::pin(async move {
        let mut guard = fd.ready(Interest::ERROR).await?;
        guard.clear_ready_matching(Ready::ERROR);
        Ok(())
    })
}

/// A periodic clock on the IO reactor: a `CLOCK_MONOTONIC` `timerfd`
/// registered for read readiness. Unlike a tokio timer it needs no time
/// driver — only the IO driver every `AsyncFd` already needs.
pub(crate) struct ProbeTimer {
    fd: AsyncFd<OwnedFd>,
}

impl ProbeTimer {
    /// Fire every `every` (at least 1 ns), the first time one period from
    /// now. Must be called in the context of a tokio runtime.
    pub(crate) fn new(every: Duration) -> io::Result<Self> {
        // SAFETY: plain syscall; no pointers.
        let raw = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh fd we own exclusively.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let every = every.max(Duration::from_nanos(1));
        let period = libc::timespec {
            tv_sec: every.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
            tv_nsec: every.subsec_nanos() as libc::c_long,
        };
        let spec = libc::itimerspec {
            it_interval: period,
            it_value: period,
        };
        // SAFETY: `spec` is a valid itimerspec; a null old-value pointer is
        // allowed.
        if unsafe { libc::timerfd_settime(fd.as_raw_fd(), 0, &spec, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is an `OwnedFd` moved into the `AsyncFd`: it stays
        // open, and refers to the same timer, until the `AsyncFd` drops.
        let fd = unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }
            .map_err(io::Error::from)?;
        Ok(Self { fd })
    }

    /// `Ready` once the timer expired (any number of times) since the last
    /// tick; consumes the expirations.
    pub(crate) fn poll_tick(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let mut expirations = [0u8; 8];
            // SAFETY: an 8-byte buffer for timerfd's 8-byte expiration count.
            let n = unsafe {
                libc::read(
                    self.fd.get_ref().as_raw_fd(),
                    expirations.as_mut_ptr().cast(),
                    expirations.len(),
                )
            };
            let err = (n < 0).then(io::Error::last_os_error);
            // Drained (or stale): the next expiry raises a fresh edge.
            guard.clear_ready();
            match err {
                None if n == 8 => return Poll::Ready(Ok(())),
                None => return Poll::Ready(Err(io::Error::other("short timerfd read"))),
                Some(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Some(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    /// Wait for the next tick.
    pub(crate) async fn tick(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| self.poll_tick(cx)).await
    }
}

/// The idle probe's state: created on the first idle wait.
enum Probe {
    Unarmed,
    Armed(ProbeTimer),
    /// The timer couldn't be created (logged once): error events only.
    Unavailable,
}

/// A registration's death detection (see the module docs).
struct Liveness<T> {
    health: HealthFn<T>,
    /// Holds a clone of the registration's `Arc`.
    errors: ErrorWatch,
    probe: Probe,
    probe_every: Duration,
}

impl<T> Liveness<T> {
    /// `Ready(err)` once the source is found dead; otherwise `Pending`,
    /// with the error watch and the probe armed to wake the task.
    fn poll_dead(
        &mut self,
        fd: &Arc<AsyncFd<OwnedFd>>,
        inner: &T,
        cx: &mut Context<'_>,
    ) -> Poll<io::Error> {
        let mut events = 0;
        while let Poll::Ready(res) = self.errors.as_mut().poll(cx) {
            // The event's bit is cleared: the next watch resolves only on a
            // new edge, so a source that stays in error (down) can't spin.
            self.errors = watch_errors(fd);
            if let Err(e) = res.and_then(|()| (self.health)(inner)) {
                return Poll::Ready(e);
            }
            events += 1;
            if events == ERROR_EVENTS_PER_POLL {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        if matches!(self.probe, Probe::Unarmed) {
            self.probe = match ProbeTimer::new(self.probe_every) {
                Ok(timer) => Probe::Armed(timer),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "no liveness probe (timerfd): a source that dies without an error \
                         event won't end the wait"
                    );
                    Probe::Unavailable
                }
            };
        }
        if let Probe::Armed(timer) = &self.probe {
            while let Poll::Ready(tick) = timer.poll_tick(cx) {
                if let Err(e) = tick.and_then(|()| (self.health)(inner)) {
                    return Poll::Ready(e);
                }
            }
        }
        Poll::Pending
    }
}

/// A source plus a reactor registration on a dup of its fd — the subset of
/// the `AsyncFd<T>` API the adapters use.
pub(crate) struct Registered<T> {
    // Declared before `inner`, so the dup is deregistered and closed (when
    // the last `Arc` — `liveness` holds one — drops) before `inner` drops.
    ready: Arc<AsyncFd<OwnedFd>>,
    liveness: Liveness<T>,
    inner: T,
}

impl<T: AsFd> Registered<T> {
    /// Register a dup of `inner`'s fd for `interest` plus error events.
    /// Waits end with an error once `health` reports the source dead —
    /// checked on an error event and every [`LIVENESS_PROBE`] of idle
    /// waiting.
    pub(crate) fn new(inner: T, interest: Interest, health: HealthFn<T>) -> io::Result<Self> {
        let ready = Arc::new(register_dup(inner.as_fd(), interest | Interest::ERROR)?);
        let liveness = Liveness {
            health,
            errors: watch_errors(&ready),
            probe: Probe::Unarmed,
            probe_every: LIVENESS_PROBE,
        };
        Ok(Self {
            ready,
            liveness,
            inner,
        })
    }
}

/// Which readiness a wait is for.
#[derive(Clone, Copy)]
enum Direction {
    Read,
    Write,
}

impl<T> Registered<T> {
    pub(crate) fn get_ref(&self) -> &T {
        &self.inner
    }

    pub(crate) fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Deregister and return the source.
    pub(crate) fn into_inner(self) -> T {
        self.inner
    }

    /// Shorten the liveness probe period (tests).
    #[cfg(test)]
    fn with_probe_every(mut self, every: Duration) -> Self {
        self.liveness.probe_every = every;
        self
    }

    /// Poll for `dir` readiness, or for the source's death.
    fn poll_ready(
        &mut self,
        dir: Direction,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<ReadyMut<'_, T>>> {
        let Self {
            ready,
            liveness,
            inner,
        } = self;
        let polled = match dir {
            Direction::Read => ready.poll_read_ready(cx),
            Direction::Write => ready.poll_write_ready(cx),
        };
        if let Poll::Ready(res) = polled {
            return Poll::Ready(res.map(|guard| ReadyMut { guard, inner }));
        }
        liveness.poll_dead(ready, inner, cx).map(Err)
    }

    /// Wait for `dir` readiness (or the source's death), then take its
    /// guard.
    async fn ready_mut(&mut self, dir: Direction) -> io::Result<ReadyMut<'_, T>> {
        std::future::poll_fn(|cx| self.poll_ready(dir, cx).map(|r| r.map(drop))).await?;
        // The readiness is set and only `&mut self` can clear it: this
        // resolves at once.
        let guard = match dir {
            Direction::Read => self.ready.readable().await?,
            Direction::Write => self.ready.writable().await?,
        };
        Ok(ReadyMut {
            guard,
            inner: &mut self.inner,
        })
    }

    /// Wait for read readiness; ends with the source's error once it is
    /// found dead.
    pub(crate) async fn readable_mut(&mut self) -> io::Result<ReadyMut<'_, T>> {
        self.ready_mut(Direction::Read).await
    }

    /// Wait for write readiness; ends with the source's error once it is
    /// found dead.
    pub(crate) async fn writable_mut(&mut self) -> io::Result<ReadyMut<'_, T>> {
        self.ready_mut(Direction::Write).await
    }

    /// Poll for read readiness (same waker rules as
    /// `AsyncFd::poll_read_ready`), or for the source's death.
    pub(crate) fn poll_read_ready_mut(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<ReadyMut<'_, T>>> {
        self.poll_ready(Direction::Read, cx)
    }
}

/// Readiness guard plus mutable access to the source, mirroring
/// `AsyncFdReadyMutGuard`.
pub(crate) struct ReadyMut<'a, T> {
    guard: AsyncFdReadyGuard<'a, OwnedFd>,
    inner: &'a mut T,
}

impl<T> ReadyMut<'_, T> {
    pub(crate) fn get_inner_mut(&mut self) -> &mut T {
        self.inner
    }

    /// Clear tokio's readiness so the next wait re-arms via epoll.
    pub(crate) fn clear_ready(&mut self) {
        self.guard.clear_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn healthy<T>(_: &T) -> io::Result<()> {
        Ok(())
    }

    #[tokio::test]
    async fn readiness_follows_the_source_after_it_is_swapped_out() {
        let (a, b) = UnixDatagram::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let mut reg = Registered::new(a, Interest::READABLE, healthy).unwrap();
        // The registration is on a dup, not on the source's own fd.
        assert_ne!(reg.ready.as_raw_fd(), reg.get_ref().as_raw_fd());

        b.send(b"x").unwrap();
        let mut guard = reg.readable_mut().await.unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(guard.get_inner_mut().recv(&mut buf).unwrap(), 1);
        guard.clear_ready();

        // What `AsyncCapture::get_mut` allows: replace the source and close
        // the old one. The registration keeps its own fd open, so it stays
        // valid (the readiness it reports is the old socket's, which is the
        // caller's problem, not undefined behaviour).
        let (c, _d) = UnixDatagram::pair().unwrap();
        let old = std::mem::replace(reg.get_mut(), c);
        let old_fd = old.as_raw_fd();
        drop(old);
        assert_ne!(reg.ready.as_raw_fd(), old_fd);
        // SAFETY: fcntl(F_GETFD) only queries the fd.
        assert!(unsafe { libc::fcntl(reg.ready.as_raw_fd(), libc::F_GETFD) } >= 0);
        drop(reg);
    }

    /// A UDP socket connected to a closed localhost port, after one send:
    /// the ICMP port unreachable sets `sk_err = ECONNREFUSED` and raises
    /// `EPOLLERR` (and nothing to read). Returns once the error is pending.
    fn udp_with_pending_error() -> UdpSocket {
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect(("127.0.0.1", port)).unwrap();
        s.set_nonblocking(true).unwrap();
        s.send(b"x").unwrap();
        // poll(2) reports POLLERR without consuming the error.
        let mut pfd = libc::pollfd {
            fd: s.as_raw_fd(),
            events: 0,
            revents: 0,
        };
        // SAFETY: one valid pollfd, for the duration of the call.
        let n = unsafe { libc::poll(&mut pfd, 1, 2_000) };
        assert_eq!(n, 1, "no ICMP error within 2 s");
        assert_ne!(pfd.revents & libc::POLLERR, 0);
        s
    }

    fn take_error(s: &UdpSocket) -> io::Result<()> {
        match s.take_error()? {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// #212: an error event wakes a reader, whose health check then ends
    /// the wait with the socket's error. tokio delivers an `EPOLLERR` only
    /// to an `Interest::ERROR` waiter, so a plain read wait never woke.
    #[tokio::test]
    async fn error_readiness_wakes_a_reader() {
        let s = udp_with_pending_error();
        let mut reg = Registered::new(s, Interest::READABLE, take_error).unwrap();
        match tokio::time::timeout(Duration::from_secs(2), reg.readable_mut()).await {
            Ok(Err(e)) => assert_eq!(e.raw_os_error(), Some(libc::ECONNREFUSED)),
            Ok(Ok(_)) => panic!("readable without data"),
            Err(_) => panic!("readable_mut() still waiting 2 s after the socket error"),
        }
    }

    struct Counted<S> {
        sock: S,
        calls: AtomicUsize,
    }

    impl<S: AsFd> AsFd for Counted<S> {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.sock.as_fd()
        }
    }

    /// #212: a source that dies without any event (an AF_XDP socket's
    /// device unregistered, an AF_PACKET interface removed while down) is
    /// found by the idle liveness probe.
    #[tokio::test]
    async fn idle_probe_detects_death() {
        let (a, _b) = UnixDatagram::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let src = Counted {
            sock: a,
            calls: AtomicUsize::new(0),
        };
        let dies_on_third = |c: &Counted<UnixDatagram>| {
            if c.calls.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
                Err(io::Error::from_raw_os_error(libc::ENETDOWN))
            } else {
                Ok(())
            }
        };
        let mut reg = Registered::new(src, Interest::READABLE, dies_on_third)
            .unwrap()
            .with_probe_every(Duration::from_millis(50));
        let start = Instant::now();
        match tokio::time::timeout(Duration::from_secs(1), reg.readable_mut()).await {
            Ok(Err(e)) => assert_eq!(e.raw_os_error(), Some(libc::ENETDOWN)),
            Ok(Ok(_)) => panic!("readable without data"),
            Err(_) => panic!("no liveness probe: readable_mut() still waiting after 1 s"),
        }
        assert!(start.elapsed() >= Duration::from_millis(100));
        assert_eq!(reg.get_ref().calls.load(Ordering::SeqCst), 3);
    }

    /// The idle liveness probe needs no tokio time driver: an idle read
    /// wait on a runtime built with `enable_io()` only still probes the
    /// source (phase-1 0.32 code armed a `tokio::time::Sleep` and panicked:
    /// "timers are disabled"). A second fd, released by a watchdog thread
    /// after 2 s, bounds the wait without a timer.
    #[test]
    fn idle_probe_needs_no_time_driver() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        rt.block_on(async {
            let (a, _b) = UnixDatagram::pair().unwrap();
            a.set_nonblocking(true).unwrap();
            let src = Counted {
                sock: a,
                calls: AtomicUsize::new(0),
            };
            let dies_on_second = |c: &Counted<UnixDatagram>| {
                if c.calls.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
                    Err(io::Error::from_raw_os_error(libc::ENETDOWN))
                } else {
                    Ok(())
                }
            };
            let mut reg = Registered::new(src, Interest::READABLE, dies_on_second)
                .unwrap()
                .with_probe_every(Duration::from_millis(50));
            let (watchdog, release) = UnixDatagram::pair().unwrap();
            release.set_nonblocking(true).unwrap();
            let release = register_dup(release.as_fd(), Interest::READABLE).unwrap();
            let guard = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(2));
                let _ = watchdog.send(b"x");
            });
            tokio::select! {
                res = reg.readable_mut() => match res {
                    Err(e) => assert_eq!(e.raw_os_error(), Some(libc::ENETDOWN)),
                    Ok(_) => panic!("readable without data"),
                },
                _ = release.readable() => panic!("the idle probe never ran"),
            }
            drop(guard);
        });
    }

    /// A healthy verdict after an error event (an interface merely down)
    /// keeps waiting without re-checking in a loop: the event was cleared,
    /// and the error left pending on the socket raises no new edge.
    #[tokio::test]
    async fn transient_health_does_not_spin() {
        let src = Counted {
            sock: udp_with_pending_error(),
            calls: AtomicUsize::new(0),
        };
        let counts = |c: &Counted<UdpSocket>| {
            c.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let mut reg = Registered::new(src, Interest::READABLE, counts)
            .unwrap()
            .with_probe_every(Duration::from_secs(3600));
        let waited = tokio::time::timeout(Duration::from_millis(300), reg.readable_mut()).await;
        assert!(waited.is_err(), "nothing to read and the source is healthy");
        assert_eq!(reg.get_ref().calls.load(Ordering::SeqCst), 1);
    }

    /// Write waits are watched too (#225): a sink that is never writable
    /// and dies without an event ends its write wait.
    #[tokio::test]
    async fn idle_write_wait_is_probed() {
        let (a, _b) = UnixDatagram::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        // Fill the peer's queue: `a` stops being writable.
        while a.send(&[0u8; 1024]).is_ok() {}
        let src = Counted {
            sock: a,
            calls: AtomicUsize::new(0),
        };
        let dies_on_second = |c: &Counted<UnixDatagram>| {
            if c.calls.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
                Err(io::Error::from_raw_os_error(libc::ENETDOWN))
            } else {
                Ok(())
            }
        };
        let mut reg = Registered::new(src, Interest::WRITABLE, dies_on_second)
            .unwrap()
            .with_probe_every(Duration::from_millis(50));
        match tokio::time::timeout(Duration::from_secs(1), reg.writable_mut()).await {
            Ok(Err(e)) => assert_eq!(e.raw_os_error(), Some(libc::ENETDOWN)),
            Ok(Ok(_)) => panic!("writable with a full peer queue"),
            Err(_) => panic!("write wait not probed"),
        }
    }
}
