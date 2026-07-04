# Fingerprinting (JA3 / JA4 / JA4S / JA4X / JA4H)

netring surfaces passive fingerprints from unencrypted protocol metadata,
computed by [flowscope](https://github.com/p13marc/flowscope)'s observers.
Fingerprints identify the **software stack** on each side of a connection
without decryption — the basis for IOC matching, asset inventory, and
anomaly detection.

## What each fingerprint identifies

| Fingerprint | Source | Identifies | Format |
|-------------|--------|-----------|--------|
| **JA3**  | TLS ClientHello | client stack (legacy, MD5) | 32 hex chars |
| **JA4**  | TLS ClientHello | client stack (FoxIO, sorted, GREASE-stripped) | `t13d1516h2_8daaf6152771_b186095e22b6` |
| **JA4S** | TLS ServerHello | **server** stack (FoxIO) | `t130200_1301_a56c5b993250` |
| **JA4X** | TLS leaf X.509 cert | **certificate** issuer/subject/extension OIDs (FoxIO) | `a564fbbd9b48_5e2c5a8f4f17_8c0e391b6d8b` |
| **JA4H** | HTTP request | client stack from the **request** (method/headers/cookies, FoxIO) | `ge11nn05enus_…_…_…` |

JA4 and JA4S are complementary: JA4 says "what client software dialed
out," JA4S says "what server software answered." A JA4 + JA4S **pair**
pins a specific client↔server combination — far more specific than either
alone. **JA4X** fingerprints the server's leaf certificate (issuer / subject
/ extension OID sets) — it survives across IPs/SNIs sharing a cert and is
`None` for TLS 1.3 (the certificate is encrypted). **JA4H** is the HTTP
analogue of JA4 — the client fingerprint derived from a plaintext request.

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
JA3, JA4, JA4S, JA4X, and the flow key into one [`TlsFingerprint`] per
completed handshake:

```rust,no_run
use netring::prelude::*;
let monitor = Monitor::builder()
    .interface("eth0")
    // auto-registers the TlsHandshake protocol
    .on_fingerprint(|fp, _ctx| {
        if let Some(ja4s) = &fp.ja4s {
            println!("server {ja4s} for sni={:?}", fp.sni);
        }
        if let Some(ja4x) = &fp.ja4x {
            println!("cert {ja4x}");
        }
        Ok(())
    })
    .build()?;
```

For the HTTP client fingerprint, `on_http_fingerprint` mirrors the same
shape — it auto-registers the `Http` protocol and hands you an
[`HttpFingerprint`] (JA4H + method / host / user-agent + flow key) per
request:

```rust,no_run
use netring::prelude::*;
let monitor = Monitor::builder()
    .interface("eth0")
    .on_http_fingerprint(|fp, _ctx| {
        println!("{} host={:?} ja4h={}", fp.method.as_deref().unwrap_or("?"), fp.host, fp.ja4h);
        Ok(())
    })
    .build()?;
```

For the lower-level view, `on::<TlsHandshake>(|hs| …)` hands you the full
[`flowscope::tls::TlsHandshake`] (adds version, cipher, handshake outcome,
ECH state). `TlsFingerprint` is the identity-focused subset.

See [`examples/monitor/ja4_fingerprint.rs`](../examples/monitor/ja4_fingerprint.rs)
for a JA4 / JA4S / JA4X / JA4H blocklist IOC matcher.

### SSH, QUIC, post-quantum, and application protocol (0.29)

Beyond TLS/HTTP, the Monitor surfaces three more fingerprint families:

- **SSH (HASSH)** — `on_ssh_fingerprint` (feature `ssh`) hands you an
  `SshFingerprint` (client/server banners, HASSH + HASSH-server, KEX algorithms,
  host key) once a session's key exchange is seen.
- **QUIC** — `on_quic_fingerprint` (features `quic` + `tls`) hands you a
  `QuicFingerprint` (SNI, ALPN, version, the `q`-prefixed JA4, and the PQ
  key-share signal) per parsed QUIC Initial.
- **TLS post-quantum** — `TlsFingerprint.pq_key_share` is `true` when the
  ClientHello offered a post-quantum key-share group (e.g. X25519MLKEM768) — a
  cheap PQ-adoption signal independent of the FoxIO fingerprints.

`TlsFingerprint.app_protocol` (and `QuicFingerprint`) also carry the
`flowscope::app_proto::AppProtocol` classified from ALPN + SNI + port (e.g.
`Http2`, `DnsOverHttps`, `DnsOverTls`). For the DNS-privacy angle,
**`on_encrypted_dns`** (features `tls`/`quic`) fires an `EncryptedDns` for each
DoH/DoT/DoQ session with the resolver SNI and a known-public-resolver flag — see
[`examples/monitor/encrypted_dns.rs`](../examples/monitor/encrypted_dns.rs).

## ⚠️ Licensing — JA4S is **not** BSD; read before using commercially

The licenses **differ by fingerprint**, and this matters:

| Fingerprint | License | Commercial use |
|---|---|---|
| **JA3**, **JA4** (TLS *client*) | BSD-3-Clause, no patent | Free for any use, including resale |
| **JA4S** (TLS *server*), **JA4X** (cert), **JA4H** (HTTP) | **FoxIO License 1.1**, **patent-pending** | Internal / academic **OK**; **vendors selling or providing value to paying customers need an OEM license from FoxIO** — *even without exposing the fingerprint* |

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
`TlsFingerprint.ja4s` / `.ja4x` fields (and the entire `HttpFingerprint` type +
`on_http_fingerprint` hook for JA4H) don't even exist without `ja4plus`. You opt into
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
