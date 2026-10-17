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
//! A reader registered with [`Registered::new_rx`] also learns when its
//! source died. Two things make that necessary:
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
//! So a reader registers `Interest::ERROR` too and, while it waits, watches
//! for an error event and re-checks the source every [`LIVENESS_PROBE`] of
//! idle waiting. Either way the source's [`HealthFn`] decides: `Err` ends
//! the wait with that error, `Ok` (e.g. the interface is merely down) keeps
//! waiting. Under load the read readiness is set whenever the reader looks,
//! so neither check runs on the hot path.

use std::future::Future;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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

/// The read side's death detection (see the module docs).
struct Liveness<T> {
    health: HealthFn<T>,
    /// Holds a clone of the registration's `Arc`.
    errors: ErrorWatch,
    /// Armed on the first idle wait (a sleep needs the runtime's timer).
    probe: Option<Pin<Box<tokio::time::Sleep>>>,
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
        let every = self.probe_every;
        let probe = self
            .probe
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(every)));
        while probe.as_mut().poll(cx).is_ready() {
            if let Err(e) = (self.health)(inner) {
                return Poll::Ready(e);
            }
            let now = tokio::time::Instant::now();
            probe
                .as_mut()
                .reset(now.checked_add(every).unwrap_or(now + LIVENESS_PROBE));
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
    liveness: Option<Liveness<T>>,
    inner: T,
}

impl<T: AsFd> Registered<T> {
    /// Register a dup of `inner`'s fd for `interest` plus error events.
    /// Waits end with an error once `health` reports the source dead —
    /// checked on an error event and every [`LIVENESS_PROBE`] of idle
    /// waiting. Needs a runtime with the time driver enabled.
    pub(crate) fn new_rx(inner: T, interest: Interest, health: HealthFn<T>) -> io::Result<Self> {
        let ready = Arc::new(register_dup(inner.as_fd(), interest | Interest::ERROR)?);
        let liveness = Some(Liveness {
            health,
            errors: watch_errors(&ready),
            probe: None,
            probe_every: LIVENESS_PROBE,
        });
        Ok(Self {
            ready,
            liveness,
            inner,
        })
    }

    /// Register a dup of `inner`'s fd for `interest`, without liveness
    /// checks.
    pub(crate) fn new_tx(inner: T, interest: Interest) -> io::Result<Self> {
        let ready = Arc::new(register_dup(inner.as_fd(), interest)?);
        Ok(Self {
            ready,
            liveness: None,
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
        if let Some(l) = self.liveness.as_mut() {
            l.probe_every = every;
        }
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
        match liveness {
            Some(l) => l.poll_dead(ready, inner, cx).map(Err),
            None => Poll::Pending,
        }
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

    /// Wait for read readiness. With liveness checks ([`Self::new_rx`]),
    /// ends with the source's error once it is found dead.
    pub(crate) async fn readable_mut(&mut self) -> io::Result<ReadyMut<'_, T>> {
        self.ready_mut(Direction::Read).await
    }

    /// Wait for write readiness. With liveness checks ([`Self::new_rx`]),
    /// ends with the source's error once it is found dead.
    pub(crate) async fn writable_mut(&mut self) -> io::Result<ReadyMut<'_, T>> {
        self.ready_mut(Direction::Write).await
    }

    /// Poll for read readiness (same waker rules as
    /// `AsyncFd::poll_read_ready`), or — with liveness checks — for the
    /// source's death.
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
        let mut reg = Registered::new_rx(a, Interest::READABLE, healthy).unwrap();
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
        let mut reg = Registered::new_rx(s, Interest::READABLE, take_error).unwrap();
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
        let mut reg = Registered::new_rx(src, Interest::READABLE, dies_on_third)
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
        let mut reg = Registered::new_rx(src, Interest::READABLE, counts)
            .unwrap()
            .with_probe_every(Duration::from_secs(3600));
        let waited = tokio::time::timeout(Duration::from_millis(300), reg.readable_mut()).await;
        assert!(waited.is_err(), "nothing to read and the source is healthy");
        assert_eq!(reg.get_ref().calls.load(Ordering::SeqCst), 1);
    }

    /// A registration without liveness checks keeps waiting through an
    /// error event (what every reader did before #212).
    #[tokio::test]
    async fn tx_registration_has_no_health_checks() {
        let s = udp_with_pending_error();
        let mut reg = Registered::new_tx(s, Interest::READABLE).unwrap();
        let waited = tokio::time::timeout(Duration::from_millis(200), reg.readable_mut()).await;
        assert!(waited.is_err());
    }
}
