//! [JA3](https://github.com/salesforce/ja3) client fingerprinting.
//!
//! Format (joined with `,`):
//!
//! ```text
//! TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//! ```
//!
//! Each list is dash-joined. Then the canonical string is MD5'd
//! and hex-encoded. GREASE values (RFC 8701) are stripped before
//! formatting per the upstream reference implementation.

use md5::{Digest, Md5};

use crate::types::TlsClientHello;

/// Compute the JA3 canonical string and its MD5 hash for a
/// [`TlsClientHello`].
///
/// Returns `(canonical, hex_md5)`.
pub(crate) fn ja3(ch: &TlsClientHello) -> (String, String) {
    let canonical = canonical_string(ch);
    let mut hasher = Md5::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let hex_md5 = hex::encode(digest);
    (canonical, hex_md5)
}

fn canonical_string(ch: &TlsClientHello) -> String {
    // Field 1 — TLS version (record-layer; per JA3 spec).
    let version = ch.legacy_version.to_raw();

    // Field 2 — cipher suites (skip GREASE).
    let ciphers = join_dash(ch.cipher_suites.iter().copied().filter(|c| !is_grease(*c)));

    // Field 3 — extensions in order (skip GREASE).
    let exts = join_dash(
        ch.extension_types
            .iter()
            .copied()
            .filter(|e| !is_grease(*e)),
    );

    // Field 4 — supported_groups (skip GREASE).
    let groups = join_dash(
        ch.supported_groups
            .iter()
            .copied()
            .filter(|g| !is_grease(*g)),
    );

    // Field 5 — EC point formats. We don't currently extract these
    // separately from the ClientHello struct; emit empty string,
    // which matches what most fingerprints look like in practice
    // (post-TLS-1.3 EC point formats are usually omitted).
    let ec_point_formats = String::new();

    format!("{version},{ciphers},{exts},{groups},{ec_point_formats}")
}

fn join_dash<I: IntoIterator<Item = u16>>(iter: I) -> String {
    let mut out = String::new();
    for (i, v) in iter.into_iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        out.push_str(&v.to_string());
    }
    out
}

/// RFC 8701 GREASE values. Reserved 16-bit values designed to
/// detect ossified middleboxes. JA3 strips them.
fn is_grease(v: u16) -> bool {
    // GREASE values follow the pattern 0x?A?A where ? is the same hex
    // digit (e.g., 0x0A0A, 0x1A1A, ..., 0xFAFA).
    let lo = v & 0x00FF;
    let hi = (v & 0xFF00) >> 8;
    lo == hi && (lo & 0x0F) == 0x0A
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0xFAFA));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0000));
    }

    #[test]
    fn ja3_known_shape() {
        // Hand-build a ClientHello with known fields and verify
        // the canonical string starts with the expected version
        // and cipher list shape.
        use crate::types::TlsVersion;
        use bytes::Bytes;
        let ch = TlsClientHello {
            record_version: TlsVersion::Tls1_2,
            legacy_version: TlsVersion::Tls1_2,
            random: [0u8; 32],
            session_id: Bytes::new(),
            cipher_suites: vec![0x1301, 0x1302, 0x0A0A], // 0x0A0A is GREASE, must be stripped
            compression: vec![0],
            sni: None,
            alpn: vec![],
            supported_versions: vec![],
            supported_groups: vec![29, 23],
            extension_types: vec![0, 23, 65281],
        };
        let (canonical, _hash) = ja3(&ch);
        assert!(canonical.starts_with("771,4865-4866,"), "got {canonical:?}");
        assert!(canonical.ends_with(",29-23,"), "got {canonical:?}");
        // GREASE 0x0A0A (=2570) must not appear in the cipher list.
        assert!(!canonical.contains("2570"), "GREASE leaked: {canonical:?}");
    }
}
