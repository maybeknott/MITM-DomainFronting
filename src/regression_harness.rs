#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsObservation {
    pub ja3_string: String,
    pub ja3_hash_md5: String,
    pub ja4_string: String,
    pub alpn: String,
    pub h2_settings_ids: Vec<u16>,
    pub h2_settings_values: Vec<(u16, u32)>,
    pub tls_extension_order: Vec<u16>,
    pub grease_structurally_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTlsProfile {
    pub profile_name: String,
    pub expected_ja3_hash_md5: String,
    pub expected_ja4_string: String,
    pub expected_alpn: String,
    pub expected_h2_settings_ids: Vec<u16>,
    pub expected_h2_settings_values: Vec<(u16, u32)>,
    pub expected_tls_extension_order: Vec<u16>,
    pub require_grease_validity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegressionResult {
    pub passed: bool,
    pub failures: Vec<String>,
}

pub fn evaluate_profile(
    observed: &TlsObservation,
    expected: &ExpectedTlsProfile,
) -> RegressionResult {
    let mut failures = Vec::new();

    if observed.ja3_hash_md5 != expected.expected_ja3_hash_md5 {
        failures.push(format!(
            "ja3_hash_mismatch expected={} observed={}",
            expected.expected_ja3_hash_md5, observed.ja3_hash_md5
        ));
    }

    if observed.ja4_string != expected.expected_ja4_string {
        failures.push(format!(
            "ja4_mismatch expected={} observed={}",
            expected.expected_ja4_string, observed.ja4_string
        ));
    }

    if observed.alpn != expected.expected_alpn {
        failures.push(format!(
            "alpn_mismatch expected={} observed={}",
            expected.expected_alpn, observed.alpn
        ));
    }

    // HTTP/2 SETTINGS order is itself a fingerprinting signal: passive
    // fingerprinters (e.g. Akamai's HTTP/2 client fingerprint, JA4H) key on the
    // *ordered* sequence of SETTINGS identifiers as they appear on the wire, not
    // merely the set of values present. Comparing as an unordered set could
    // green-light a profile whose reordered SETTINGS would be flagged in the
    // wild, giving a false sense of evasion fidelity. Compare the exact ordered
    // sequence so the harness fails closed on any reordering or duplication.
    if !expected.expected_h2_settings_ids.is_empty()
        && observed.h2_settings_ids != expected.expected_h2_settings_ids
    {
        failures.push(format!(
            "h2_settings_mismatch expected={:?} observed={:?}",
            expected.expected_h2_settings_ids, observed.h2_settings_ids
        ));
    }

    // Some fingerprinters also incorporate SETTINGS values (id:value pairs) in
    // addition to order. Keep this optional for backwards compatibility: an
    // empty expected vector means "not checked".
    if !expected.expected_h2_settings_values.is_empty()
        && observed.h2_settings_values != expected.expected_h2_settings_values
    {
        failures.push(format!(
            "h2_settings_values_mismatch expected={:?} observed={:?}",
            expected.expected_h2_settings_values, observed.h2_settings_values
        ));
    }

    // TLS extension type order is a primary ClientHello fingerprint axis (JA3).
    // Optional for backwards compatibility: an empty expected vector means skip.
    if !expected.expected_tls_extension_order.is_empty()
        && observed.tls_extension_order != expected.expected_tls_extension_order
    {
        failures.push(format!(
            "tls_extension_order_mismatch expected={:?} observed={:?}",
            expected.expected_tls_extension_order, observed.tls_extension_order
        ));
    }

    if expected.require_grease_validity && !observed.grease_structurally_valid {
        failures.push("grease_invalid".to_string());
    }

    RegressionResult {
        passed: failures.is_empty(),
        failures,
    }
}

/// Build a [`TlsObservation`] from a parsed ClientHello for runtime self-audit.
pub fn observation_from_client_hello(hello: &crate::parser::ClientHelloInfo) -> TlsObservation {
    let ja3 = crate::ja3::compute_ja3(hello);
    let alpn = hello
        .alpn
        .first()
        .map(|proto| String::from_utf8_lossy(proto).into_owned())
        .unwrap_or_default();
    TlsObservation {
        ja3_string: ja3.ja3_string,
        ja3_hash_md5: ja3.ja3_hash_md5,
        ja4_string: String::new(),
        alpn,
        h2_settings_ids: Vec::new(),
        h2_settings_values: Vec::new(),
        tls_extension_order: hello.extension_order.clone(),
        grease_structurally_valid: !looks_like_malformed_grease(&hello.extension_order),
    }
}

/// Detect extension types that mimic GREASE shape (low nibble `0xA` on both bytes) but are not valid GREASE.
pub fn looks_like_malformed_grease(extension_order: &[u16]) -> bool {
    extension_order.iter().copied().any(|ext| {
        let hi = (ext >> 8) as u8;
        let lo = (ext & 0xff) as u8;
        (hi & 0x0f) == 0x0a && (lo & 0x0f) == 0x0a && hi != lo
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regression_passes_for_matching_observation() {
        let observed = TlsObservation {
            ja3_string: "771,4865-4866-4867,0-11-10-35-16-5-13,29-23-24,0".to_string(),
            ja3_hash_md5: "79d076b78678efd08d467f5fd487f8a7".to_string(),
            ja4_string: "t13d1516h2_8daaf6152771_02713d6af862".to_string(),
            alpn: "h2".to_string(),
            h2_settings_ids: vec![1, 3, 4, 6],
            h2_settings_values: vec![],
            tls_extension_order: vec![],
            grease_structurally_valid: true,
        };
        let expected = ExpectedTlsProfile {
            profile_name: "chrome-sample".to_string(),
            expected_ja3_hash_md5: "79d076b78678efd08d467f5fd487f8a7".to_string(),
            expected_ja4_string: "t13d1516h2_8daaf6152771_02713d6af862".to_string(),
            expected_alpn: "h2".to_string(),
            // Must match the observed order exactly: SETTINGS order is part of
            // the HTTP/2 fingerprint.
            expected_h2_settings_ids: vec![1, 3, 4, 6],
            expected_h2_settings_values: vec![],
            expected_tls_extension_order: vec![],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(result.passed);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn regression_fails_when_h2_settings_are_reordered() {
        // Same set of SETTINGS identifiers, different order. Because SETTINGS
        // order is fingerprinted, this must be treated as a mismatch rather than
        // silently passing.
        let observed = TlsObservation {
            ja3_string: "x".to_string(),
            ja3_hash_md5: "hash".to_string(),
            ja4_string: "ja4".to_string(),
            alpn: "h2".to_string(),
            h2_settings_ids: vec![1, 3, 4, 6],
            h2_settings_values: vec![],
            tls_extension_order: vec![],
            grease_structurally_valid: true,
        };
        let expected = ExpectedTlsProfile {
            profile_name: "reordered".to_string(),
            expected_ja3_hash_md5: "hash".to_string(),
            expected_ja4_string: "ja4".to_string(),
            expected_alpn: "h2".to_string(),
            expected_h2_settings_ids: vec![6, 4, 1, 3],
            expected_h2_settings_values: vec![],
            expected_tls_extension_order: vec![],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(!result.passed, "reordered SETTINGS must not pass");
        assert!(result
            .failures
            .iter()
            .any(|f| f.starts_with("h2_settings_mismatch")));
    }

    #[test]
    fn regression_reports_all_mismatches() {
        let observed = TlsObservation {
            ja3_string: "x".to_string(),
            ja3_hash_md5: "aaaa".to_string(),
            ja4_string: "ja4-a".to_string(),
            alpn: "http/1.1".to_string(),
            h2_settings_ids: vec![1, 2],
            h2_settings_values: vec![],
            tls_extension_order: vec![],
            grease_structurally_valid: false,
        };
        let expected = ExpectedTlsProfile {
            profile_name: "profile".to_string(),
            expected_ja3_hash_md5: "bbbb".to_string(),
            expected_ja4_string: "ja4-b".to_string(),
            expected_alpn: "h2".to_string(),
            expected_h2_settings_ids: vec![1, 3],
            expected_h2_settings_values: vec![],
            expected_tls_extension_order: vec![],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(!result.passed);
        assert!(result
            .failures
            .iter()
            .any(|f| f.starts_with("ja3_hash_mismatch")));
        assert!(result
            .failures
            .iter()
            .any(|f| f.starts_with("ja4_mismatch")));
        assert!(result
            .failures
            .iter()
            .any(|f| f.starts_with("alpn_mismatch")));
        assert!(result
            .failures
            .iter()
            .any(|f| f.starts_with("h2_settings_mismatch")));
        assert!(result.failures.iter().any(|f| f == "grease_invalid"));
    }

    #[test]
    fn regression_fails_when_h2_settings_values_diverge() {
        let observed = TlsObservation {
            ja3_string: "x".to_string(),
            ja3_hash_md5: "hash".to_string(),
            ja4_string: "ja4".to_string(),
            alpn: "h2".to_string(),
            h2_settings_ids: vec![1, 3, 4, 6],
            h2_settings_values: vec![(1, 100), (3, 0), (4, 1), (6, 262144)],
            tls_extension_order: vec![],
            grease_structurally_valid: true,
        };
        let expected = ExpectedTlsProfile {
            profile_name: "values-mismatch".to_string(),
            expected_ja3_hash_md5: "hash".to_string(),
            expected_ja4_string: "ja4".to_string(),
            expected_alpn: "h2".to_string(),
            expected_h2_settings_ids: vec![],
            expected_h2_settings_values: vec![(1, 100), (3, 0), (4, 0), (6, 262144)],
            expected_tls_extension_order: vec![],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(!result.passed);
        assert!(result
            .failures
            .iter()
            .any(|f| f.starts_with("h2_settings_values_mismatch")));
    }

    #[test]
    fn regression_fails_when_tls_extension_order_diverges() {
        let observed = TlsObservation {
            ja3_string: "x".to_string(),
            ja3_hash_md5: "hash".to_string(),
            ja4_string: "ja4".to_string(),
            alpn: "h2".to_string(),
            h2_settings_ids: vec![],
            h2_settings_values: vec![],
            tls_extension_order: vec![0, 11, 10, 35],
            grease_structurally_valid: true,
        };
        let expected = ExpectedTlsProfile {
            profile_name: "extorder-mismatch".to_string(),
            expected_ja3_hash_md5: "hash".to_string(),
            expected_ja4_string: "ja4".to_string(),
            expected_alpn: "h2".to_string(),
            expected_h2_settings_ids: vec![],
            expected_h2_settings_values: vec![],
            expected_tls_extension_order: vec![0, 10, 11, 35],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(!result.passed);
        assert!(result
            .failures
            .iter()
            .any(|f| f.starts_with("tls_extension_order_mismatch")));
    }

    #[test]
    fn malformed_grease_does_not_flag_supported_groups_extension() {
        assert!(!looks_like_malformed_grease(&[0x000a]));
        assert!(looks_like_malformed_grease(&[0x0a1a]));
    }

    #[test]
    fn observation_from_client_hello_populates_ja3_and_extension_order() {
        use crate::parser::ClientHelloInfo;

        let hello = ClientHelloInfo {
            sni: None,
            alpn: vec![b"h2".to_vec()],
            supported_versions: vec![0x0304],
            signature_algorithms: Vec::new(),
            supported_groups: vec![0x001d],
            extension_order: vec![0x0000, 0x0010],
            cipher_suites: vec![0x1301],
            ec_point_formats: vec![0],
            raw_len: 0,
        };
        let obs = observation_from_client_hello(&hello);
        assert_eq!(obs.ja3_string, "772,4865,0-16,29,0");
        assert_eq!(obs.ja3_hash_md5.len(), 32);
        assert_eq!(obs.alpn, "h2");
        assert_eq!(obs.tls_extension_order, vec![0x0000, 0x0010]);
        assert!(obs.grease_structurally_valid);
    }

    #[test]
    fn self_audit_round_trip_via_evaluate_profile() {
        use crate::parser::ClientHelloInfo;

        let hello = ClientHelloInfo {
            sni: None,
            alpn: vec![b"h2".to_vec()],
            supported_versions: vec![0x0304],
            signature_algorithms: Vec::new(),
            supported_groups: vec![0x001d],
            extension_order: vec![0x0000, 0x0010],
            cipher_suites: vec![0x1301],
            ec_point_formats: vec![0],
            raw_len: 0,
        };
        let observed = observation_from_client_hello(&hello);
        let expected = ExpectedTlsProfile {
            profile_name: "live".to_string(),
            expected_ja3_hash_md5: observed.ja3_hash_md5.clone(),
            expected_ja4_string: String::new(),
            expected_alpn: "h2".to_string(),
            expected_h2_settings_ids: vec![],
            expected_h2_settings_values: vec![],
            expected_tls_extension_order: vec![0x0000, 0x0010],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(result.passed, "{:?}", result.failures);
    }
}
