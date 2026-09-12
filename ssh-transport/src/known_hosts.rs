//! Host-key blob helpers the transport itself needs (S1, PLAN.md §3.6):
//! fingerprint formatting for the accepted-host-keys log and the
//! plausibility check the host-key test pins. Verbatim copies of
//! terminal-core's `known_hosts` codecs — that crate must compile without
//! this OPTIONAL dependency, so it keeps its own FFI-exported originals;
//! keep the two sides in sync (both sides carry their own #[cfg(test)] pins).

/// `SHA256:` + unpadded standard base64 of the wire blob (H5 — identical
/// on both platforms, cross-checked against each platform's own
/// fingerprint helper in their suites).
pub fn blob_fingerprint(blob: &[u8]) -> String {
    // SHA-256 by hand is not worth a hand-roll: sha2 is already pinned.
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(blob);
    format!("SHA256:{}", base64_encode(&digest).trim_end_matches('='))
}

/// Android's `isPlausibleKeyBlob`, ported byte-exactly: a known_hosts key
/// blob must open with an ssh string naming a known key-algorithm family;
/// garbage blobs (truncated base64, arbitrary data) must not create
/// entries — otherwise they'd read as changed keys instead of being
/// skipped (OpenSSH ignores lines whose key it cannot parse). Note it
/// validates the BLOB-embedded algorithm only, not agreement with the
/// line's algorithm field.
pub fn is_plausible_blob(blob: &[u8]) -> bool {
    if blob.len() < 4 {
        return false;
    }
    let len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if len < 4 || len > blob.len() - 4 {
        return false;
    }
    let alg = &blob[4..4 + len];
    let alg = match std::str::from_utf8(alg) {
        Ok(a) => a,
        Err(_) => return false,
    };
    (alg.starts_with("ssh-")
        || alg.starts_with("ecdsa-")
        || alg.starts_with("sk-ssh-")
        || alg.starts_with("x509v3-"))
        && alg.bytes().all(|b| (32..=126).contains(&b))
}

/// Standard base64 with padding (the write side of `base64_decode`).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirrors terminal-core's known_hosts test fixtures BYTE-EXACTLY so both
    // copies of the codecs are pinned to the same values — the review of the
    // S1 split flagged that the original usage (lib.rs's host-key-verifier
    // test) skips when the sshd matrix is down, leaving the copy unpinned in
    // plain `cargo test`.

    /// terminal-core's ED fixture, decoded: len-prefixed "ssh-ed25519" +
    /// len-prefixed bytes 0x01..=0x20.
    fn ed_blob() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&11u32.to_be_bytes());
        v.extend_from_slice(b"ssh-ed25519");
        v.extend_from_slice(&32u32.to_be_bytes());
        v.extend((1u8..=32).collect::<Vec<u8>>());
        v
    }

    /// Wire blob from raw parts (terminal-core's raw_blob: each part is
    /// length-prefixed on the wire).
    fn raw_blob(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(&(p.len() as u32).to_be_bytes());
            out.extend_from_slice(p);
        }
        out
    }

    #[test]
    fn plausibility_is_android_ported_byte_exactly() {
        assert!(is_plausible_blob(&ed_blob()));
        assert!(is_plausible_blob(&raw_blob(&[b"ssh-rsa", &[0xAB; 32]])));
        assert!(!is_plausible_blob(&raw_blob(&["AAAA".as_bytes()])));
        assert!(!is_plausible_blob(b"ABCDEF".to_vec().as_slice()));
        assert!(!is_plausible_blob(&[]));
        assert!(!is_plausible_blob(&[0, 0, 0]));
        // embedded length beyond the buffer
        assert!(!is_plausible_blob(&[0, 0, 1, 0, b's']));
        // embedded algorithm must look like an algorithm family
        assert!(!is_plausible_blob(&raw_blob(&[
            b"hello",
            &[1u8, 2, 3, 4, 5, 6, 7, 8]
        ])));
    }

    #[test]
    fn fingerprint_is_sha256_unpadded() {
        let fp = blob_fingerprint(&ed_blob());
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.contains('='));
        assert_eq!(fp.len(), 7 + 43); // SHA-256 → 43 unpadded base64 chars
                                      // The literal pins BOTH copies (terminal-core asserts the same
                                      // value for the same fixture bytes): any divergence between the
                                      // S1-duplicated implementations fails one side.
        assert_eq!(
            blob_fingerprint(&ed_blob()),
            "SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4"
        );
        // RSA-format blobs fingerprint too (different wire length).
        assert!(blob_fingerprint(&raw_blob(&[b"ssh-rsa", &[0xAB; 32]])).starts_with("SHA256:"));
    }
}
