use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::io::Read;
use std::path::PathBuf;

use secretscan::{patterns, redact, store::Store};

#[derive(Parser)]
#[command(
    name = "secretscan",
    about = "SecretScan — Real-time secret & credential detector for Claude Code",
    long_about = "Scans text, files, and Claude Code tool outputs for API keys, tokens,\nprivate keys, database URLs, and 50+ other secret formats.\n\nDetected secrets are redacted with [REDACTED:type:fingerprint] placeholders.\nOriginals are stored locally in SQLite for recovery — never sent anywhere.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Verbose logging
    #[arg(long, short, global = true)]
    verbose: bool,

    /// SQLite database path
    #[arg(long, global = true, default_value = "~/.secretscan/secretscan.db")]
    db_path: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan text, a file, or stdin for secrets
    Scan {
        /// File path or '-' for stdin
        #[arg(default_value = "-")]
        input: String,

        /// Redact detected secrets in the output
        #[arg(long, short)]
        redact: bool,

        /// Minimum severity to report (low, medium, high, critical)
        #[arg(long, default_value = "low")]
        severity: String,
    },

    /// PostToolUse / PreToolUse hook mode (reads hook JSON from stdin)
    Hook {
        /// Session ID
        #[arg(long, default_value = "unknown")]
        session: String,
    },

    /// Expand a redacted secret by fingerprint (local recovery only)
    Expand {
        /// Fingerprint from [REDACTED:type:FINGERPRINT]
        fingerprint: String,
    },

    /// Add a fingerprint to the allowlist (mark as safe / not a secret)
    Allow {
        /// Fingerprint to allowlist
        fingerprint: String,

        /// Reason for allowlisting
        #[arg(long, short)]
        reason: Option<String>,
    },

    /// Remove a fingerprint from the allowlist
    Unallow {
        /// Fingerprint to remove
        fingerprint: String,
    },

    /// Show scan statistics
    Stats,

    /// List recent findings
    Audit {
        /// Number of findings to show
        #[arg(long, default_value = "20")]
        limit: usize,
    },

    /// List all active patterns (built-in + custom)
    Patterns,

    /// Auto-install hook into ~/.claude/settings.json
    Setup {
        /// Preview without writing
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let db_path = resolve_db_path(&cli.db_path)?;

    match cli.command {
        Commands::Scan { input, redact, severity } => {
            let text = read_input(&input)?;
            let min_sev = parse_severity(&severity);

            let all_findings = patterns::scan_all(&text);

            // Filter out allowlisted fingerprints
            let store = Store::open(&db_path).ok();
            let findings: Vec<_> = all_findings
                .into_iter()
                .filter(|f| {
                    store.as_ref()
                        .map(|s| !s.is_allowed(&f.fingerprint).unwrap_or(false))
                        .unwrap_or(true)
                })
                .collect();

            // Record findings to DB
            if let Some(ref s) = store {
                for f in &findings {
                    let _ = s.record_finding(f, None, "cli");
                }
                if !findings.is_empty() {
                    let _ = s.record_scan("cli", None, text.len(), findings.len(), 0);
                }
            }

            let filtered: Vec<_> = findings
                .iter()
                .filter(|f| f.severity >= min_sev)
                .collect();

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&filtered)?);
                return Ok(());
            }

            if filtered.is_empty() {
                println!("{}", "✅  No secrets detected.".green());
                return Ok(());
            }

            eprintln!(
                "{}",
                format!("🚨  {} secret{} found:", filtered.len(),
                    if filtered.len() == 1 { "" } else { "s" }).red().bold()
            );
            eprintln!();
            for f in &filtered {
                eprintln!(
                    "  {} {:8}  {:<40}  fingerprint: {}",
                    f.severity.emoji(),
                    format!("[{}]", f.severity.as_str().to_uppercase())
                        .bold(),
                    f.pattern_name,
                    f.fingerprint.dimmed()
                );
                let preview = if f.matched.len() > 40 {
                    format!("{}…", &f.matched[..37])
                } else {
                    f.matched.clone()
                };
                eprintln!("             {}", preview.dimmed());
                eprintln!();
            }

            if redact {
                let result = redact::scan_and_redact(&text, None, &db_path, "cli");
                print!("{}", result.redacted_text);
            }

            // Exit code 1 if any High/Critical found
            let has_critical = filtered.iter().any(|f| {
                f.severity >= secretscan::Severity::High
            });
            if has_critical {
                std::process::exit(1);
            }
        }

        Commands::Hook { session } => {
            let mut raw = String::new();
            std::io::stdin().read_to_string(&mut raw)?;

            let result = secretscan::hook::process(&raw, &db_path, &session)?;
            print!("{result}");

            // Log to stderr if secrets were found
            if let Ok(output) = serde_json::from_str::<serde_json::Value>(&result) {
                if let Some(meta) = output.get("secretscan") {
                    let found = meta.get("secrets_found")
                        .and_then(|v| v.as_u64()).unwrap_or(0);
                    if found > 0 {
                        eprintln!(
                            "[secretscan] 🚨 {} secret{} redacted from {} output",
                            found,
                            if found == 1 { "" } else { "s" },
                            output.get("tool_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("tool")
                        );
                    }
                }
            }
        }

        Commands::Expand { fingerprint } => {
            let store = Store::open(&db_path)?;
            match store.get_original(&fingerprint)? {
                Some(original) => {
                    if cli.json {
                        println!("{}", serde_json::json!({ "fingerprint": fingerprint, "original": original }));
                    } else {
                        println!("{original}");
                    }
                }
                None => {
                    eprintln!("No record found for fingerprint: {fingerprint}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Allow { fingerprint, reason } => {
            let store = Store::open(&db_path)?;
            store.allow(&fingerprint, reason.as_deref())?;
            if cli.json {
                println!("{}", serde_json::json!({ "allowed": fingerprint, "reason": reason }));
            } else {
                println!("✅  {} added to allowlist.", fingerprint.green());
            }
        }

        Commands::Unallow { fingerprint } => {
            let store = Store::open(&db_path)?;
            let removed = store.unallow(&fingerprint)?;
            if cli.json {
                println!("{}", serde_json::json!({ "removed": removed, "fingerprint": fingerprint }));
            } else if removed {
                println!("✅  {} removed from allowlist.", fingerprint.green());
            } else {
                println!("ℹ️   {} was not on the allowlist.", fingerprint);
            }
        }

        Commands::Stats => {
            let store = Store::open(&db_path)?;
            let stats = store.stats()?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!("{}", "SecretScan Statistics".bold());
                println!("{}", "─".repeat(45));
                println!("  Total scans:          {}", stats.total_scans);
                println!("  Bytes scanned:        {}", format_bytes(stats.total_bytes_scanned));
                println!("  Secrets found:        {}", stats.total_secrets_found);
                println!("  Secrets redacted:     {}", stats.total_secrets_redacted);
                println!("  Unique secrets seen:  {}", stats.unique_secrets);
                println!("  Allowlist entries:    {}", stats.allowlist_count);
                if !stats.by_severity.is_empty() {
                    println!();
                    println!("  By severity:");
                    for (sev, count) in &stats.by_severity {
                        println!("    {:<10} {}", sev, count);
                    }
                }
            }
        }

        Commands::Audit { limit } => {
            let store = Store::open(&db_path)?;
            let findings = store.recent_findings(limit)?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
                return Ok(());
            }

            if findings.is_empty() {
                println!("No findings recorded yet.");
                return Ok(());
            }

            println!("{}", format!("Recent {} findings:", findings.len()).bold());
            println!("{}", "─".repeat(70));
            for f in &findings {
                println!(
                    "  {}  {:<12}  {:<35}  {}",
                    f.fingerprint.dimmed(),
                    f.severity.bold(),
                    f.pattern_name,
                    f.detected_at.dimmed()
                );
            }
        }

        Commands::Patterns => {
            let builtin_count = *patterns::BUILTIN_COUNT;
            let total = patterns::PATTERNS.len();
            let custom_count = total - builtin_count;

            if cli.json {
                let list: Vec<_> = patterns::PATTERNS.iter().enumerate().map(|(i, p)| {
                    serde_json::json!({
                        "id": p.id,
                        "name": p.name,
                        "severity": p.severity.as_str(),
                        "source": patterns::pattern_source(i)
                    })
                }).collect();
                println!("{}", serde_json::to_string_pretty(&list)?);
                return Ok(());
            }

            println!(
                "{}",
                format!(
                    "Active patterns ({total}): {builtin_count} built-in, {custom_count} custom"
                ).bold()
            );
            println!("{}", "─".repeat(75));
            for (i, p) in patterns::PATTERNS.iter().enumerate() {
                let source = patterns::pattern_source(i);
                let source_tag = if source == "custom" {
                    "[custom]".yellow().to_string()
                } else {
                    String::new()
                };
                println!(
                    "  {} {:8}  {:<20}  {}  {}",
                    p.severity.emoji(),
                    format!("[{}]", p.severity.as_str().to_uppercase()),
                    p.id,
                    p.name,
                    source_tag
                );
            }
        }

        Commands::Setup { dry_run } => {
            run_setup(dry_run, &cli.json)?;
        }
    }

    Ok(())
}

// ─── Setup ────────────────────────────────────────────────────────────────────

fn run_setup(dry_run: bool, json: &bool) -> Result<()> {
    let settings_path = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".claude/settings.json")
    };

    let binary = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "secretscan".to_string());

    let hook_command = format!("{binary} hook --session ${{CLAUDE_SESSION_ID:-default}}");

    // Read existing settings
    let mut settings = if settings_path.exists() {
        let data = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str::<serde_json::Value>(&data).unwrap_or(serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Check if already configured
    let already = is_already_configured(&settings);

    if already {
        let msg = "SecretScan hook already configured — nothing to do.";
        if *json {
            println!("{}", serde_json::json!({ "already_configured": true, "message": msg }));
        } else {
            println!("✅  {msg}");
        }
        return Ok(());
    }

    if !dry_run {
        // Inject hook
        let hook_entry = serde_json::json!({
            "matcher": "*",
            "hooks": [{ "type": "command", "command": hook_command }]
        });
        let hooks = settings
            .as_object_mut()
            .unwrap()
            .entry("hooks")
            .or_insert(serde_json::json!({}));
        let ptu = hooks
            .as_object_mut()
            .unwrap()
            .entry("PostToolUse")
            .or_insert(serde_json::json!([]));
        if let Some(arr) = ptu.as_array_mut() {
            arr.push(hook_entry);
        }

        // Atomic write
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = settings_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&settings)?)?;
        std::fs::rename(&tmp, &settings_path)?;
    }

    let message = if dry_run {
        format!("[DRY RUN] Would add PostToolUse hook to {}", settings_path.display())
    } else {
        format!(
            "PostToolUse hook added to {}.\nRestart Claude Code to activate.",
            settings_path.display()
        )
    };

    if *json {
        println!("{}", serde_json::json!({
            "configured": !dry_run,
            "dry_run": dry_run,
            "settings_path": settings_path,
            "hook_command": hook_command,
            "message": message
        }));
    } else {
        println!("✅  {message}");
        println!();
        println!("  Settings: {}", settings_path.display());
        println!("  Command:  {hook_command}");
    }

    Ok(())
}

fn is_already_configured(settings: &serde_json::Value) -> bool {
    let Some(hooks) = settings.get("hooks") else { return false };
    let Some(ptu) = hooks.get("PostToolUse") else { return false };
    let Some(arr) = ptu.as_array() else { return false };
    arr.iter().any(|entry| {
        entry.get("hooks")
            .and_then(|h| h.as_array())
            .map(|hs| hs.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("secretscan"))
                    .unwrap_or(false)
            }))
            .unwrap_or(false)
            || entry.get("command")
                .and_then(|c| c.as_str())
                .map(|c| c.contains("secretscan"))
                .unwrap_or(false)
    })
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn resolve_db_path(raw: &str) -> Result<PathBuf> {
    let expanded = if raw.starts_with("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(&raw[2..])
    } else {
        PathBuf::from(raw)
    };
    if let Some(parent) = expanded.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(expanded)
}

fn read_input(input: &str) -> Result<String> {
    if input == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(input)
            .map_err(|e| anyhow::anyhow!("failed to read {input}: {e}"))
    }
}

fn parse_severity(s: &str) -> secretscan::Severity {
    match s.to_lowercase().as_str() {
        "medium" | "med" => secretscan::Severity::Medium,
        "high"           => secretscan::Severity::High,
        "critical"       => secretscan::Severity::Critical,
        _                => secretscan::Severity::Low,
    }
}

fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
