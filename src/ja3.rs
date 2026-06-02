//! JA3 TLS client fingerprinting, computed from a parsed [`ClientHelloInfo`].
//!
//! JA3 hashes the five colon-separated fields: SSL version, cipher suites,
//! extension types, supported groups, and EC point formats. GREASE values (RFC
//! 8701) are stripped before hashing so the fingerprint matches passive tools.

use crate::parser::ClientHelloInfo;

/// Observed JA3 fingerprint: canonical string and MD5 hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3Fingerprint {
    pub ja3_string: String,
    pub ja3_hash_md5: String,
}

/// Compute JA3 string and MD5 hash for a parsed ClientHello.
pub fn compute_ja3(hello: &ClientHelloInfo) -> Ja3Fingerprint {
    let ja3_string = ja3_string(hello);
    let ja3_hash_md5 = md5_hex(ja3_string.as_bytes());
    Ja3Fingerprint {
        ja3_string,
        ja3_hash_md5,
    }
}

/// RFC 8701 GREASE: both bytes equal and each has low nibble `0xA`.
pub fn is_grease(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

pub fn ja3_string(hello: &ClientHelloInfo) -> String {
    let version = ja3_ssl_version(hello);
    let ciphers = join_u16_filtered(&hello.cipher_suites);
    let extensions = join_u16_filtered(&hello.extension_order);
    let curves = join_u16_filtered(&hello.supported_groups);
    let point_formats = hello
        .ec_point_formats
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{version},{ciphers},{extensions},{curves},{point_formats}",
        version = version,
        ciphers = ciphers,
        extensions = extensions,
        curves = curves,
        point_formats = point_formats
    )
}

pub fn ja3_hash(hello: &ClientHelloInfo) -> String {
    md5_hex(ja3_string(hello).as_bytes())
}

fn ja3_ssl_version(hello: &ClientHelloInfo) -> u16 {
    let mut versions: Vec<u16> = hello
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    if versions.is_empty() {
        return 0x0303;
    }
    versions.sort_unstable();
    *versions.last().unwrap_or(&0x0303)
}

fn join_u16_filtered(values: &[u16]) -> String {
    values
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn md5_hex(data: &[u8]) -> String {
    let digest = md5(data);
    let mut out = String::with_capacity(32);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let start = i * 4;
            *word = u32::from_le_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a, b, c, d);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((bb & cc) | (!bb & dd), i),
                16..=31 => ((dd & bb) | (!dd & cc), (5 * i + 1) % 16),
                32..=47 => (bb ^ cc ^ dd, (3 * i + 5) % 16),
                _ => (cc ^ (bb | !dd), (7 * i) % 16),
            };
            let temp = dd;
            dd = cc;
            cc = bb;
            bb = bb.wrapping_add(
                aa.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            aa = temp;
        }
        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }
    let mut out = [0u8; 16];
    for (i, word) in [a, b, c, d].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ClientHelloInfo;

    fn hello_with(
        versions: Vec<u16>,
        ciphers: Vec<u16>,
        extensions: Vec<u16>,
        curves: Vec<u16>,
        point_formats: Vec<u8>,
    ) -> ClientHelloInfo {
        ClientHelloInfo {
            sni: None,
            alpn: Vec::new(),
            supported_versions: versions,
            signature_algorithms: Vec::new(),
            supported_groups: curves,
            extension_order: extensions,
            cipher_suites: ciphers,
            ec_point_formats: point_formats,
            raw_len: 0,
        }
    }

    #[test]
    fn is_grease_recognizes_rfc8701_values() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x000a));
    }

    #[test]
    fn ja3_string_strips_grease_and_joins_fields() {
        let hello = hello_with(
            vec![0x0a0a, 0x0304, 0x0303],
            vec![0x1a1a, 0x1301, 0x1302],
            vec![0x0000, 0x000a, 0x0010],
            vec![0x001d, 0x0017],
            vec![0],
        );
        assert_eq!(ja3_string(&hello), "772,4865-4866,0-10-16,29-23,0");
    }

    #[test]
    fn ja3_string_handles_empty_optional_fields() {
        let hello = hello_with(vec![0x0303], vec![0x1301], vec![0x0000], vec![], vec![]);
        assert_eq!(ja3_string(&hello), "771,4865,0,,");
    }

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn compute_ja3_bundles_consistent_string_and_hash() {
        let hello = hello_with(
            vec![0x0a0a, 0x0304, 0x0303],
            vec![0x1301, 0x1302],
            vec![0x0000, 0x000a],
            vec![0x001d],
            vec![0],
        );
        let fp = compute_ja3(&hello);
        assert_eq!(fp.ja3_string, ja3_string(&hello));
        assert_eq!(fp.ja3_hash_md5, md5_hex(fp.ja3_string.as_bytes()));
        assert_eq!(fp.ja3_hash_md5.len(), 32);
    }
}
