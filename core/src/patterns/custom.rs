//! Load user-defined patterns from ~/.secretscan/patterns.toml

use crate::Severity;
use regex::Regex;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use super::Pattern;

/// On-disk representation of a custom pattern.
#[derive(Debug, Deserialize)]
struct PatternEntry {
    name: String,
    regex: String,
    severity: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    min_entropy: Option<f64>,
}

/// Top-level config file structure.
#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    patterns: Vec<PatternEntry>,
}

/// Default config path: ~/.secretscan/patterns.toml
pub fn default_config_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".secretscan/patterns.toml"))
}

/// Load custom patterns from the config file.
///
/// Returns an empty vec if the file doesn't exist.
/// Warns and skips individual patterns with invalid regex.
pub fn load_custom_patterns() -> Vec<Pattern> {
    let Some(path) = default_config_path() else {
        return Vec::new();
    };
    load_from_path(&path)
}

/// Load custom patterns from a specific path (testable).
pub fn load_from_path(path: &Path) -> Vec<Pattern> {
    if !path.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to read {}: {e}", path.display());
            return Vec::new();
        }
    };

    let config: ConfigFile = match toml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse {}: {e}", path.display());
            return Vec::new();
        }
    };

    info!("Loading {} custom pattern(s) from {}", config.patterns.len(), path.display());

    let mut result = Vec::new();
    for entry in config.patterns {
        let regex = match Regex::new(&entry.regex) {
            Ok(r) => r,
            Err(e) => {
                warn!("Skipping custom pattern '{}': invalid regex: {e}", entry.name);
                continue;
            }
        };

        let severity = parse_severity(&entry.severity);

        // Leak strings so they live for 'static — these are loaded once at startup.
        let id: &'static str = Box::leak(entry.name.clone().into_boxed_str());
        let name: &'static str = match entry.description {
            Some(d) => Box::leak(d.into_boxed_str()),
            None => id,
        };

        result.push(Pattern {
            id,
            name,
            severity,
            regex,
            min_entropy: entry.min_entropy,
            context_keywords: &[],
        });
    }

    result
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" | "med" => Severity::Medium,
        "high" => Severity::High,
        "critical" | "crit" => Severity::Critical,
        other => {
            warn!("Unknown severity '{other}', defaulting to Medium");
            Severity::Medium
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("patterns.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"
[[patterns]]
name = "internal_token"
regex = "itk_[a-zA-Z0-9]{{32}}"
severity = "high"
description = "Internal API Token"

[[patterns]]
name = "bad_regex"
regex = "[invalid("
severity = "low"
"#).unwrap();

        let patterns = load_from_path(&path);
        // Should load 1 valid pattern, skip the bad regex
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id, "internal_token");
        assert_eq!(patterns[0].name, "Internal API Token");
        assert_eq!(patterns[0].severity, Severity::High);
    }

    #[test]
    fn test_load_missing_file() {
        let patterns = load_from_path(Path::new("/nonexistent/patterns.toml"));
        assert!(patterns.is_empty());
    }
}
