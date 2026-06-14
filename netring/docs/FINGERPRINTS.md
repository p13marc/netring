# TLS fingerprinting (JA3 / JA4 / JA4S)

netring surfaces passive TLS fingerprints from the unencrypted handshake,
computed by [flowscope](https://github.com/p13marc/flowscope)'s TLS
observer. Fingerprints identify the **software stack** on each side of a
connection without decryption — the basis for IOC matching, asset
inventory, and anomaly detection.

## What each fingerprint identifies

| Fingerprint | Source | Identifies | Format |
|-------------|--------|-----------|--------|
| **JA3**  | ClientHello | client stack (legacy, MD5) | 32 hex chars |
| **JA4**  | ClientHello | client stack (FoxIO, sorted, GREASE-stripped) | `t13d1516h2_8daaf6152771_b186095e22b6` |
| **JA4S** | ServerHello | **server** stack (FoxIO) | `t130200_1301_a56c5b993250` |

JA4 and JA4S are complementary: JA4 says "what client software dialed
out," JA4S says "what server software answered." A JA4 + JA4S **pair**
pins a specific client↔server combination — far more specific than either
alone.

### JA4 vs JA4S construction

- **JA4** sorts the cipher and extension lists (resilient to client-side
  randomization) and strips GREASE (RFC 8701).
- **JA4S** hashes the server's extension list **in observed order** —
  servers don't shuffle, so their order is itself a signal — GREASE
  stripped. The cipher section is the single suite the server chose.
- Both encode the ALPN as the first + last character of the chosen
  protocol (`http/1.1` → `h1`, `h2` → `h2`).

## Using fingerprints in a Monitor

The ergonomic entry point is `on_fingerprint`, which bundles SNI, ALPN,
JA3, JA4, JA4S, and the flow key into one [`TlsFingerprint`] per completed
handshake:

```rust,no_run
use netring::prelude::*;
# fn _ex() -> Result<(), netring::Error> {
let monitor = Monitor::builder()
    .interface("eth0")
    // auto-registers the TlsHandshake protocol
    .on_fingerprint(|fp, _ctx| {
        if let Some(ja4s) = &fp.ja4s {
            println!("server {ja4s} for sni={:?}", fp.sni);
        }
        Ok(())
    })
    .build()?;
# let _ = monitor;
# Ok(())
# }
```

For the lower-level view, `on::<TlsHandshake>(|hs| …)` hands you the full
[`flowscope::tls::TlsHandshake`] (adds version, cipher, handshake outcome,
ECH state). `TlsFingerprint` is the identity-focused subset.

See [`examples/monitor/ja4_fingerprint.rs`](../examples/monitor/ja4_fingerprint.rs)
for a JA4/JA4S blocklist IOC matcher.

## Licensing note

JA4 and JA4S (the **base** algorithms used here) are **BSD-3-Clause** and
free for any use. The broader **JA4+** suite (JA4H, JA4L, JA4X, JA4SSH, …)
is licensed by FoxIO under a separate, more restrictive license for
commercial products — netring does **not** implement JA4+, only the
BSD-licensed JA4 / JA4S. If you add JA4+ algorithms, review the FoxIO
license: <https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md>.

## Enabling

Fingerprinting needs the `tls` feature (which pulls flowscope's
`tls-fingerprints`). The `TlsHandshakeParser` enables JA3/JA4/JA4S
computation by default; without the feature, the fingerprint fields are
all `None`.

[`TlsFingerprint`]: https://docs.rs/netring/latest/netring/monitor/struct.TlsFingerprint.html
[`flowscope::tls::TlsHandshake`]: https://docs.rs/flowscope/latest/flowscope/tls/struct.TlsHandshake.html
