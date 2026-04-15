pub mod builtin;
pub mod custom;
pub mod entropy;

use crate::{Finding, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

/// A compiled secret pattern.
pub struct Pattern {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub regex: Regex,
    /// Minimum entropy threshold (bits/char). None = skip entropy check.
    pub min_entropy: Option<f64>,
    /// Context keywords that raise confidence (e.g. "password", "secret")
    pub context_keywords: &'static [&'static str],
}

impl Pattern {
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for m in self.regex.find_iter(text) {
            let matched = m.as_str();

            // Entropy gate
            if let Some(min_e) = self.min_entropy {
                if entropy::shannon(matched) < min_e {
                    continue;
                }
            }

            // Build short fingerprint (last 8 hex chars of blake3)
            let hash = blake3::hash(matched.as_bytes());
            let fingerprint = format!("{:.8}", hash.to_hex());

            findings.push(Finding {
                pattern_id: self.id,
                pattern_name: self.name,
                severity: self.severity,
                matched: matched.to_string(),
                redacted: format!("[REDACTED:{}:{}]", self.id, fingerprint),
                fingerprint,
                offset: m.start(),
                length: matched.len(),
            });
        }
        findings
    }
}

/// Number of built-in patterns (set once at init).
pub static BUILTIN_COUNT: Lazy<usize> = Lazy::new(|| builtin::all_patterns().len());

/// All compiled patterns (built-in + custom), initialised once.
pub static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    let mut patterns = builtin::all_patterns();
    let custom = custom::load_custom_patterns();
    if !custom.is_empty() {
        tracing::info!("Loaded {} custom pattern(s)", custom.len());
    }
    patterns.extend(custom);
    patterns
});

/// Returns whether a pattern at the given index is built-in or custom.
pub fn pattern_source(index: usize) -> &'static str {
    if index < *BUILTIN_COUNT { "built-in" } else { "custom" }
}

/// Scan text against all registered patterns.
pub fn scan_all(text: &str) -> Vec<Finding> {
    let mut findings: Vec<Finding> = PATTERNS.iter().flat_map(|p| p.scan(text)).collect();

    // Add entropy-based generic detection
    findings.extend(entropy::scan_high_entropy(text));

    // Sort by offset, deduplicate overlapping findings (keep highest severity)
    findings.sort_by_key(|f| f.offset);
    dedup_overlapping(findings)
}

fn dedup_overlapping(findings: Vec<Finding>) -> Vec<Finding> {
    let mut result: Vec<Finding> = Vec::new();
    for f in findings {
        if let Some(last) = result.last_mut() {
            let last_end = last.offset + last.length;
            if f.offset < last_end {
                // Overlapping — keep the higher severity one
                if f.severity > last.severity {
                    *last = f;
                }
                continue;
            }
        }
        result.push(f);
    }
    result
}
