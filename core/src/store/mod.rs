//! SQLite-backed store for redaction records and allowlist management.
//! Originals are stored locally only — never sent anywhere.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

use crate::Finding;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).context("failed to open secretscan database")?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            -- Each detected secret (before redaction)
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                pattern_id  TEXT NOT NULL,
                pattern_name TEXT NOT NULL,
                severity    TEXT NOT NULL,
                original    TEXT NOT NULL,
                tool_name   TEXT,
                session_id  TEXT,
                detected_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);

            -- Allowlist: known-safe strings that should not be flagged
            CREATE TABLE IF NOT EXISTS allowlist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                reason      TEXT,
                added_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
            );

            -- Session statistics
            CREATE TABLE IF NOT EXISTS scan_stats (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT NOT NULL,
                tool_name    TEXT,
                scanned_bytes INTEGER DEFAULT 0,
                secrets_found INTEGER DEFAULT 0,
                secrets_redacted INTEGER DEFAULT 0,
                scanned_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
            );
            ",
        ).context("failed to initialize schema")?;
        Ok(())
    }

    /// Store a finding. Returns false if it's on the allowlist.
    pub fn record_finding(
        &self,
        finding: &Finding,
        tool_name: Option<&str>,
        session_id: &str,
    ) -> Result<bool> {
        // Check allowlist first
        if self.is_allowed(&finding.fingerprint)? {
            return Ok(false);
        }

        self.conn.execute(
            "INSERT OR IGNORE INTO findings
             (fingerprint, pattern_id, pattern_name, severity, original, tool_name, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                finding.fingerprint,
                finding.pattern_id,
                finding.pattern_name,
                finding.severity.as_str(),
                finding.matched,
                tool_name,
                session_id,
            ],
        )?;
        Ok(true)
    }

    /// Retrieve original text by fingerprint (local recovery).
    pub fn get_original(&self, fingerprint: &str) -> Result<Option<String>> {
        let result = self.conn.query_row(
            "SELECT original FROM findings WHERE fingerprint = ?1 LIMIT 1",
            params![fingerprint],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Check if a fingerprint is on the allowlist.
    pub fn is_allowed(&self, fingerprint: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM allowlist WHERE fingerprint = ?1",
            params![fingerprint],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Add a fingerprint to the allowlist.
    pub fn allow(&self, fingerprint: &str, reason: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO allowlist (fingerprint, reason) VALUES (?1, ?2)",
            params![fingerprint, reason],
        )?;
        Ok(())
    }

    /// Remove a fingerprint from the allowlist.
    pub fn unallow(&self, fingerprint: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM allowlist WHERE fingerprint = ?1",
            params![fingerprint],
        )?;
        Ok(n > 0)
    }

    /// Record a scan event (for stats).
    pub fn record_scan(
        &self,
        session_id: &str,
        tool_name: Option<&str>,
        scanned_bytes: usize,
        found: usize,
        redacted: usize,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO scan_stats (session_id, tool_name, scanned_bytes, secrets_found, secrets_redacted)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session_id,
                tool_name,
                scanned_bytes as i64,
                found as i64,
                redacted as i64,
            ],
        )?;
        Ok(())
    }

    /// Get lifetime stats.
    pub fn stats(&self) -> Result<StoreStats> {
        let total_scans: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM scan_stats", [], |r| r.get(0))?;
        let total_bytes: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(scanned_bytes), 0) FROM scan_stats", [], |r| r.get(0))?;
        let total_found: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(secrets_found), 0) FROM scan_stats", [], |r| r.get(0))?;
        let total_redacted: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(secrets_redacted), 0) FROM scan_stats", [], |r| r.get(0))?;
        let unique_secrets: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT fingerprint) FROM findings", [], |r| r.get(0))?;
        let allowlist_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM allowlist", [], |r| r.get(0))?;

        // Breakdown by severity
        let mut by_severity = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity ORDER BY cnt DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            by_severity.push(row?);
        }

        Ok(StoreStats {
            total_scans: total_scans as usize,
            total_bytes_scanned: total_bytes as usize,
            total_secrets_found: total_found as usize,
            total_secrets_redacted: total_redacted as usize,
            unique_secrets: unique_secrets as usize,
            allowlist_count: allowlist_count as usize,
            by_severity,
        })
    }

    /// List recent findings.
    pub fn recent_findings(&self, limit: usize) -> Result<Vec<FindingRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, pattern_name, severity, tool_name, session_id, detected_at
             FROM findings ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(FindingRecord {
                fingerprint: row.get(0)?,
                pattern_name: row.get(1)?,
                severity: row.get(2)?,
                tool_name: row.get(3)?,
                session_id: row.get(4)?,
                detected_at: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().context("db read failed")
    }
}

#[derive(Debug, serde::Serialize)]
pub struct StoreStats {
    pub total_scans: usize,
    pub total_bytes_scanned: usize,
    pub total_secrets_found: usize,
    pub total_secrets_redacted: usize,
    pub unique_secrets: usize,
    pub allowlist_count: usize,
    pub by_severity: Vec<(String, i64)>,
}

#[derive(Debug, serde::Serialize)]
pub struct FindingRecord {
    pub fingerprint: String,
    pub pattern_name: String,
    pub severity: String,
    pub tool_name: Option<String>,
    pub session_id: Option<String>,
    pub detected_at: String,
}
