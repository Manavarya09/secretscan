pub mod hook;
pub mod patterns;
pub mod redact;
pub mod store;

use serde::{Deserialize, Serialize};

/// Secret severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low      => "low",
            Self::Medium   => "medium",
            Self::High     => "high",
            Self::Critical => "critical",
        }
    }

    pub fn emoji(self) -> &'static str {
        match self {
            Self::Low      => "🔵",
            Self::Medium   => "🟡",
            Self::High     => "🟠",
            Self::Critical => "🔴",
        }
    }

    pub fn color_code(self) -> &'static str {
        match self {
            Self::Low      => "\x1b[34m", // blue
            Self::Medium   => "\x1b[33m", // yellow
            Self::High     => "\x1b[91m", // bright red
            Self::Critical => "\x1b[31m", // red
        }
    }
}

/// A single secret detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub pattern_id: &'static str,
    pub pattern_name: &'static str,
    pub severity: Severity,
    /// The original matched string (stored locally, never forwarded).
    pub matched: String,
    /// Safe replacement string: `[REDACTED:pattern_id:fingerprint]`
    pub redacted: String,
    /// First 8 hex chars of blake3(matched) — used for recovery + allowlist.
    pub fingerprint: String,
    pub offset: usize,
    pub length: usize,
}

/// Result of a scan + redact operation.
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub original_len: usize,
    pub redacted_text: String,
    pub findings: Vec<Finding>,
    pub clean: bool,
}

impl ScanResult {
    pub fn summary(&self) -> String {
        if self.clean {
            return "✅  No secrets detected.".to_string();
        }
        let mut lines = vec![format!(
            "🚨  {} secret{} found:",
            self.findings.len(),
            if self.findings.len() == 1 { "" } else { "s" }
        )];
        for f in &self.findings {
            lines.push(format!(
                "  {} [{}] {} — {}",
                f.severity.emoji(),
                f.severity.as_str().to_uppercase(),
                f.pattern_name,
                f.fingerprint
            ));
        }
        lines.join("\n")
    }
}
