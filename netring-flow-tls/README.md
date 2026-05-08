# netring-flow-tls

Passive TLS handshake observer for [`netring-flow`](https://crates.io/crates/netring-flow).

[![crates.io](https://img.shields.io/crates/v/netring-flow-tls.svg)](https://crates.io/crates/netring-flow-tls)
[![docs.rs](https://img.shields.io/docsrs/netring-flow-tls)](https://docs.rs/netring-flow-tls)

## What it is

A `netring-flow::ReassemblerFactory` that bridges
[`tls-parser`](https://crates.io/crates/tls-parser) (rusticata) into
`netring-flow`'s reassembler. Receives bytes from the per-flow TCP
byte stream, emits parsed `TlsClientHello` / `TlsServerHello` /
`TlsAlert` events via a user-supplied `TlsHandler` callback.

**Passive only** — no decryption, no MITM, no session keys. We see
what's on the wire in cleartext: the handshake until ChangeCipherSpec
in TLS 1.2, or the unencrypted prefix in TLS 1.3 (ClientHello +
ServerHello).

## Quick start

```rust,no_run
use netring_flow_tls::{TlsFactory, TlsHandler, TlsClientHello};

struct Logger;
impl TlsHandler for Logger {
    fn on_client_hello(&self, h: &TlsClientHello) {
        println!(
            "SNI={:?} ALPN={:?} ciphers={}",
            h.sni, h.alpn, h.cipher_suites.len()
        );
    }
}

// Wire into a netring FlowStream:
//   cap.flow_stream(FiveTuple::bidirectional())
//      .with_reassembler(TlsFactory::with_handler(Logger));
```

## What's surfaced

- **ClientHello**: legacy version, random, session ID, cipher suites
  (in order, GREASE included), compression methods, SNI, ALPN list,
  `supported_versions` extension, `supported_groups`, full
  extension-type list (ordered, useful for fingerprinting).
- **ServerHello**: legacy + `supported_versions`, random, session ID,
  selected cipher, ALPN selection.
- **Alerts**: level (Warning / Fatal) + RFC 5246 §7.2 description code.

## What's not surfaced

- **Anything past ChangeCipherSpec / encrypted records**: by design.
  Use a TLS-decrypting tool if you have keys.
- **Certificate parsing**: out of scope (use [`x509-parser`](https://crates.io/crates/x509-parser)
  on the certificate bytes from a separate `Certificate` handshake
  message — would be a v0.2 addition).
- **Session resumption details / PSK**: not tracked.
- **HelloRetryRequest**: not separately surfaced (looks like a
  ServerHello to the parser).

## Optional: JA3 fingerprinting

Enable the `ja3` feature:

```toml
[dependencies]
netring-flow-tls = { version = "0.1", features = ["ja3"] }
```

Then set `TlsConfig::ja3 = true` and implement `on_ja3` in your
handler:

```rust,ignore
use netring_flow_tls::{TlsConfig, TlsFactory, TlsHandler};

struct H;
impl TlsHandler for H {
    fn on_ja3(&self, hash_md5: &str, canonical: &str) {
        println!("JA3: {hash_md5} = {canonical}");
    }
}

let factory = TlsFactory::with_config(H, TlsConfig {
    ja3: true,
    ..Default::default()
});
```

GREASE values (RFC 8701) are stripped from the canonical string per
the upstream JA3 reference.

JA4 is on the roadmap (`ja4` feature) but not yet implemented.

## License

Dual MIT / Apache-2.0 (your choice).
