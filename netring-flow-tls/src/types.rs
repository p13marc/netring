use bytes::Bytes;

/// Parsed TLS ClientHello — what the client offered to the server.
#[derive(Debug, Clone)]
pub struct TlsClientHello {
    /// Record-layer protocol version (the version on the outer
    /// record, often `Tls1_0` for TLS 1.3 ClientHellos for
    /// middlebox-compat reasons).
    pub record_version: TlsVersion,
    /// `legacy_version` field on the ClientHello message itself.
    pub legacy_version: TlsVersion,
    /// 32-byte client random (Unix timestamp prefix on TLS 1.0–1.2;
    /// fully random on TLS 1.3).
    pub random: [u8; 32],
    /// Session ID. TLS 1.3 fakes this for compat; in TLS 1.2 a
    /// non-empty value indicates an attempted session resumption.
    pub session_id: Bytes,
    /// Offered cipher suites in order.
    pub cipher_suites: Vec<u16>,
    /// Compression methods offered.
    pub compression: Vec<u8>,
    /// Server name (SNI) extension value, if present.
    pub sni: Option<String>,
    /// Negotiated ALPN protocols offered by the client.
    pub alpn: Vec<String>,
    /// `supported_versions` extension (TLS 1.3+).
    pub supported_versions: Vec<TlsVersion>,
    /// `supported_groups` (key-exchange named curves).
    pub supported_groups: Vec<u16>,
    /// Extension types in the order they appeared. Useful for
    /// fingerprinting (JA3, JA4).
    pub extension_types: Vec<u16>,
}

/// Parsed TLS ServerHello.
#[derive(Debug, Clone)]
pub struct TlsServerHello {
    pub record_version: TlsVersion,
    pub legacy_version: TlsVersion,
    pub random: [u8; 32],
    pub session_id: Bytes,
    /// The cipher suite the server picked.
    pub cipher_suite: u16,
    pub compression: u8,
    /// Negotiated ALPN protocol, if the extension was present and
    /// the server selected one.
    pub alpn: Option<String>,
    /// `supported_versions` extension — present in TLS 1.3 to
    /// signal the actual negotiated version.
    pub supported_version: Option<TlsVersion>,
}

/// TLS Alert record (RFC 5246 §7.2).
#[derive(Debug, Clone, Copy)]
pub struct TlsAlert {
    pub level: TlsAlertLevel,
    pub description: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsAlertLevel {
    Warning,
    Fatal,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    Ssl3_0,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
    Other(u16),
}

impl TlsVersion {
    /// Map a raw 16-bit version number from the wire to a `TlsVersion`.
    pub fn from_raw(v: u16) -> Self {
        match v {
            0x0300 => TlsVersion::Ssl3_0,
            0x0301 => TlsVersion::Tls1_0,
            0x0302 => TlsVersion::Tls1_1,
            0x0303 => TlsVersion::Tls1_2,
            0x0304 => TlsVersion::Tls1_3,
            other => TlsVersion::Other(other),
        }
    }

    /// Reverse of [`from_raw`](Self::from_raw).
    pub fn to_raw(self) -> u16 {
        match self {
            TlsVersion::Ssl3_0 => 0x0300,
            TlsVersion::Tls1_0 => 0x0301,
            TlsVersion::Tls1_1 => 0x0302,
            TlsVersion::Tls1_2 => 0x0303,
            TlsVersion::Tls1_3 => 0x0304,
            TlsVersion::Other(v) => v,
        }
    }
}

/// User implements this to receive parsed TLS handshake events.
pub trait TlsHandler: Send + Sync + 'static {
    /// ClientHello observed (initiator side).
    fn on_client_hello(&self, _hello: &TlsClientHello) {}
    /// ServerHello observed (responder side).
    fn on_server_hello(&self, _hello: &TlsServerHello) {}
    /// Alert observed in either direction.
    fn on_alert(&self, _alert: &TlsAlert) {}

    /// Optional: receive the JA3 fingerprint for a ClientHello.
    /// Only fires when the `ja3` feature is enabled.
    #[cfg(feature = "ja3")]
    fn on_ja3(&self, _hash_md5: &str, _canonical: &str) {}
}

/// Tunables for the TLS observer.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Compute JA3 fingerprints for every ClientHello (requires
    /// `ja3` feature). Default: `false` even with the feature on.
    pub ja3: bool,
    /// Maximum bytes buffered per direction before the reassembler
    /// gives up and goes Desynced. Defaults to 64 KiB — TLS records
    /// are 16 KiB max each; the handshake usually fits in 1–3 records.
    pub max_buffer: usize,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ja3: false,
            max_buffer: 64 * 1024,
        }
    }
}
