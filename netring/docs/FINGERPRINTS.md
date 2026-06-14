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

## ⚠️ Licensing — JA4S is **not** BSD; read before using commercially

The licenses **differ by fingerprint**, and this matters:

| Fingerprint | License | Commercial use |
|---|---|---|
| **JA3**, **JA4** (TLS *client*) | BSD-3-Clause, no patent | Free for any use, including resale |
| **JA4S** (TLS *server*) | **FoxIO License 1.1**, **patent-pending** | Internal / academic **OK**; **vendors selling or providing value to paying customers need an OEM license from FoxIO** — *even without exposing the fingerprint* |

JA4S is part of the **JA4+** suite (JA4S/JA4H/JA4L/JA4X/JA4SSH/…), which
FoxIO licenses under the [FoxIO License 1.1] and describes as patent-pending.
netring's / flowscope's JA4S is an independent implementation of the public
algorithm, but that **does not** exempt downstream commercial users from
FoxIO's license + patent-pending terms. If you ship a product that uses
JA4S, get an OEM license. Read the FoxIO [License FAQ] first.

**Staying BSD-clean (the default):** since 0.25, JA4S lives behind the opt-in
**`ja4plus`** cargo feature (off by default, and excluded from the `monitor` /
`all-parsers` umbrellas). The default TLS fingerprint surface — JA3 + JA4
(client), enabled by the `tls` feature — is BSD-only / royalty-free, and the
`TlsFingerprint.ja4s` field doesn't even exist without `ja4plus`. You opt into
the FoxIO-licensed JA4S consciously; enabling `ja4plus` pulls flowscope's
`ja4plus` (FoxIO License 1.1) into your build.

[FoxIO License 1.1]: https://github.com/FoxIO-LLC/ja4
[License FAQ]: https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md

## Enabling

- **JA3 + JA4 (client)** — enable the **`tls`** feature (which pulls flowscope's
  `tls-fingerprints`). Royalty-free / BSD.
- **JA4S (server)** — additionally enable the opt-in **`ja4plus`** feature
  (FoxIO License 1.1; pulls `flowscope/ja4plus`). This is what makes the
  `TlsFingerprint.ja4s` field exist. Off by default — read the licensing
  section above before enabling it commercially.

The `TlsHandshakeParser` computes the fingerprints its features allow; without
the feature, the corresponding fields are `None` (or, for `ja4s`, absent).

[`TlsFingerprint`]: https://docs.rs/netring/latest/netring/monitor/struct.TlsFingerprint.html
[`flowscope::tls::TlsHandshake`]: https://docs.rs/flowscope/latest/flowscope/tls/struct.TlsHandshake.html
