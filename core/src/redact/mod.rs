//! Redaction engine — replaces detected secrets in text with safe placeholders.

use crate::{Finding, ScanResult};

/// Apply all findings to the text, replacing each matched secret with its
/// redacted placeholder. Edits are applied in reverse order so byte offsets
/// stay valid.
///
/// Safety: validates that each offset falls on a UTF-8 character boundary
/// and that the text at the offset actually matches the expected secret
/// before replacing. Skips findings that fail validation rather than
/// panicking or silently corrupting text.
pub fn apply_redactions(text: &str, findings: &[Finding]) -> String {
    let mut result = text.to_string();
    // Sort descending by offset so we don't invalidate later offsets
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| b.offset.cmp(&a.offset));

    for f in &sorted {
        let end = f.offset + f.length;

        // Bounds check
        if end > result.len() {
            tracing::warn!(
                fingerprint = %f.fingerprint,
                "Skipping redaction: offset {}..{} out of bounds (text len {})",
                f.offset, end, result.len()
            );
            continue;
        }

        // UTF-8 boundary check — replace_range panics if indices are
        // not on character boundaries.
        if !result.is_char_boundary(f.offset) || !result.is_char_boundary(end) {
            tracing::warn!(
                fingerprint = %f.fingerprint,
                "Skipping redaction: offset {}..{} is not on a UTF-8 character boundary",
                f.offset, end
            );
            continue;
        }

        // Verify the text at this offset still matches the expected secret.
        // This prevents silent data corruption if findings are stale or
        // applied to the wrong text.
        if &result[f.offset..end] != f.matched {
            tracing::warn!(
                fingerprint = %f.fingerprint,
                "Skipping redaction: text at offset {}..{} does not match expected secret",
                f.offset, end
            );
            continue;
        }

        result.replace_range(f.offset..end, &f.redacted);
    }
    result
}

/// Full scan + redact pipeline. Returns the redacted text and scan metadata.
pub fn scan_and_redact(
    text: &str,
    tool_name: Option<&str>,
    db_path: &std::path::Path,
    session_id: &str,
) -> ScanResult {
    use crate::patterns;
    use crate::store::Store;

    let findings = patterns::scan_all(text);

    // Filter out allowlisted findings
    let store = Store::open(db_path).ok();
    let active_findings: Vec<Finding> = if let Some(ref s) = store {
        findings
            .into_iter()
            .filter(|f| !s.is_allowed(&f.fingerprint).unwrap_or(false))
            .collect()
    } else {
        findings
    };

    // Record findings to DB
    if let Some(ref s) = store {
        for f in &active_findings {
            let _ = s.record_finding(f, tool_name, session_id);
        }
        let _ = s.record_scan(
            session_id,
            tool_name,
            text.len(),
            active_findings.len(),
            active_findings.len(),
        );
    }

    let redacted_text = apply_redactions(text, &active_findings);
    let clean = active_findings.is_empty();

    ScanResult {
        original_len: text.len(),
        redacted_text,
        findings: active_findings,
        clean,
    }
}
