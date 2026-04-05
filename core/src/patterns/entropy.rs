//! Shannon entropy analysis for detecting high-entropy strings that look like secrets.

use crate::{Finding, Severity};
use regex::Regex;
use once_cell::sync::Lazy;

/// Minimum entropy (bits per character) to flag as suspicious.
const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
/// Minimum length for entropy analysis.
const MIN_SECRET_LENGTH: usize = 20;
/// Maximum length (avoid flagging long base64 payloads like JWT bodies).
const MAX_SECRET_LENGTH: usize = 200;

/// Compute Shannon entropy of a string in bits per character.
pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Regex for candidate high-entropy tokens: alphanumeric + common secret chars.
static CANDIDATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[A-Za-z0-9+/=_\-]{20,200}").unwrap()
});

/// Context keywords that, if nearby, raise the flag from INFO to MEDIUM.
static CONTEXT_KW_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(secret|password|passwd|pwd|token|key|api[_\-]?key|credential|auth|private|bearer|access[_\-]?key)")
        .unwrap()
});

/// Scan for generic high-entropy strings.
pub fn scan_high_entropy(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for m in CANDIDATE_RE.find_iter(text) {
        let s = m.as_str();
        if s.len() < MIN_SECRET_LENGTH || s.len() > MAX_SECRET_LENGTH {
            continue;
        }

        let e = shannon(s);
        if e < HIGH_ENTROPY_THRESHOLD {
            continue;
        }

        // Skip if it looks like a base64-encoded UUID or hash (common false positive)
        if looks_like_hash(s) {
            continue;
        }

        // Determine severity by context
        let context_start = m.start().saturating_sub(80);
        let context_end = (m.end() + 80).min(text.len());
        let context = &text[context_start..context_end];
        let severity = if CONTEXT_KW_RE.is_match(context) {
            Severity::Medium
        } else {
            Severity::Low
        };

        let hash = blake3::hash(s.as_bytes());
        let fingerprint = format!("{:.8}", hash.to_hex());

        findings.push(Finding {
            pattern_id: "high_entropy",
            pattern_name: "High-entropy string",
            severity,
            matched: s.to_string(),
            redacted: format!("[REDACTED:high_entropy:{}]", fingerprint),
            fingerprint,
            offset: m.start(),
            length: s.len(),
        });
    }

    findings
}

/// Heuristic: looks like a hex hash (md5/sha256/blake3) — lower false-positive risk.
fn looks_like_hash(s: &str) -> bool {
    let hex_chars = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
    let ratio = hex_chars as f64 / s.len() as f64;
    // If >90% hex digits and length is 32, 40, 56, or 64 — it's probably a hash
    ratio > 0.90 && matches!(s.len(), 32 | 40 | 56 | 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_repeated_char() {
        assert!(shannon("aaaaaaaaaa") < 1.0);
    }

    #[test]
    fn entropy_of_random_string() {
        // A real API key-like string should have high entropy
        let s = "xK9mP2nQ8rL5vT1wJ4hB7cF0dA3sE6uI";
        assert!(shannon(s) > 4.0);
    }

    #[test]
    fn hash_not_flagged() {
        // SHA256-like hex string should not be flagged
        let s = "a3f5c2d1e4b6a7f8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
        assert!(looks_like_hash(s));
    }

    #[test]
    fn high_entropy_detected() {
        let text = "api_key = xK9mP2nQ8rL5vT1wJ4hB7cF0dA3sE6uI";
        let findings = scan_high_entropy(text);
        assert!(!findings.is_empty());
    }
}
