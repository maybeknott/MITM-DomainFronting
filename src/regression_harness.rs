use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsObservation {
    pub ja3_string: String,
    pub ja3_hash_md5: String,
    pub ja4_string: String,
    pub alpn: String,
    pub h2_settings_ids: Vec<u16>,
    pub grease_structurally_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTlsProfile {
    pub profile_name: String,
    pub expected_ja3_hash_md5: String,
    pub expected_ja4_string: String,
    pub expected_alpn: String,
    pub expected_h2_settings_ids: Vec<u16>,
    pub require_grease_validity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegressionResult {
    pub passed: bool,
    pub failures: Vec<String>,
}

pub fn evaluate_profile(observed: &TlsObservation, expected: &ExpectedTlsProfile) -> RegressionResult {
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

    let expected_settings: BTreeSet<u16> = expected.expected_h2_settings_ids.iter().copied().collect();
    let observed_settings: BTreeSet<u16> = observed.h2_settings_ids.iter().copied().collect();
    if expected_settings != observed_settings {
        failures.push(format!(
            "h2_settings_mismatch expected={:?} observed={:?}",
            expected_settings, observed_settings
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
            grease_structurally_valid: true,
        };
        let expected = ExpectedTlsProfile {
            profile_name: "chrome-sample".to_string(),
            expected_ja3_hash_md5: "79d076b78678efd08d467f5fd487f8a7".to_string(),
            expected_ja4_string: "t13d1516h2_8daaf6152771_02713d6af862".to_string(),
            expected_alpn: "h2".to_string(),
            expected_h2_settings_ids: vec![6, 4, 1, 3],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(result.passed);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn regression_reports_all_mismatches() {
        let observed = TlsObservation {
            ja3_string: "x".to_string(),
            ja3_hash_md5: "aaaa".to_string(),
            ja4_string: "ja4-a".to_string(),
            alpn: "http/1.1".to_string(),
            h2_settings_ids: vec![1, 2],
            grease_structurally_valid: false,
        };
        let expected = ExpectedTlsProfile {
            profile_name: "profile".to_string(),
            expected_ja3_hash_md5: "bbbb".to_string(),
            expected_ja4_string: "ja4-b".to_string(),
            expected_alpn: "h2".to_string(),
            expected_h2_settings_ids: vec![1, 3],
            require_grease_validity: true,
        };
        let result = evaluate_profile(&observed, &expected);
        assert!(!result.passed);
        assert!(result.failures.iter().any(|f| f.starts_with("ja3_hash_mismatch")));
        assert!(result.failures.iter().any(|f| f.starts_with("ja4_mismatch")));
        assert!(result.failures.iter().any(|f| f.starts_with("alpn_mismatch")));
        assert!(result.failures.iter().any(|f| f.starts_with("h2_settings_mismatch")));
        assert!(result.failures.iter().any(|f| f == "grease_invalid"));
    }
}
