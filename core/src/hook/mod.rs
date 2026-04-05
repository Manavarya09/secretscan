//! Claude Code hook handler.
//! Reads PostToolUse / PreToolUse JSON from stdin, redacts secrets, writes to stdout.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::redact;

/// Claude Code PostToolUse hook input format.
#[derive(Debug, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub tool_output: String,
}

/// Hook output — same shape as input with redacted fields.
#[derive(Debug, Serialize)]
pub struct HookOutput {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secretscan: Option<HookMeta>,
}

#[derive(Debug, Serialize)]
pub struct HookMeta {
    pub secrets_found: usize,
    pub redacted: Vec<String>,
    pub clean: bool,
}

/// Process a hook call: scan + redact tool_output and tool_input values.
pub fn process(raw: &str, db_path: &Path, session_id: &str) -> Result<String> {
    let input: HookInput = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => {
            // Not a valid hook payload — pass through unchanged
            return Ok(raw.to_string());
        }
    };

    let tool_name = input.tool_name.as_str();

    // Redact tool_output
    let output_result = redact::scan_and_redact(
        &input.tool_output,
        Some(tool_name),
        db_path,
        session_id,
    );

    // Redact tool_input (serialized to string for scanning)
    let input_str = serde_json::to_string(&input.tool_input).unwrap_or_default();
    let input_result = redact::scan_and_redact(
        &input_str,
        Some(tool_name),
        db_path,
        session_id,
    );
    let redacted_input: serde_json::Value =
        serde_json::from_str(&input_result.redacted_text).unwrap_or(input.tool_input);

    let total_found = output_result.findings.len() + input_result.findings.len();
    let mut all_redacted: Vec<String> = output_result
        .findings
        .iter()
        .map(|f| format!("{} ({})", f.pattern_name, f.severity.as_str()))
        .collect();
    all_redacted.extend(
        input_result
            .findings
            .iter()
            .map(|f| format!("{} ({})", f.pattern_name, f.severity.as_str())),
    );

    let meta = if total_found > 0 {
        Some(HookMeta {
            secrets_found: total_found,
            redacted: all_redacted,
            clean: false,
        })
    } else {
        None
    };

    let output = HookOutput {
        tool_name: tool_name.to_string(),
        tool_input: redacted_input,
        tool_output: output_result.redacted_text,
        secretscan: meta,
    };

    Ok(serde_json::to_string(&output)?)
}
