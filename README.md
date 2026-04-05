# SecretScan

**Real-time secret & credential detector for Claude Code.** Blocks API keys, tokens, private keys, and database passwords from ever entering your LLM context window.

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![npm](https://img.shields.io/npm/v/@masyv/secretscan)](https://www.npmjs.com/package/@masyv/secretscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## The Problem

When Claude Code runs tools, their outputs flow directly into the context window. That includes:
- `cat .env` → your API keys
- `git log` → commit messages with accidentally committed credentials
- Database query results → connection strings, hashed passwords
- `curl` responses → tokens, JWTs, session cookies

**SecretScan intercepts every tool output** before it reaches Claude, redacts detected secrets, and logs them locally. Claude sees `[REDACTED:anthropic_api_key:bbfc6912]` — not `sk-ant-api03-...`.

## 47 Built-in Patterns

| Severity | Providers |
|----------|-----------|
| 🔴 Critical | Anthropic, OpenAI, AWS, GitHub, Stripe, Google Service Account, PostgreSQL, MySQL, MongoDB, PEM Private Keys |
| 🟠 High | GitLab, Slack, npm, SendGrid, Cloudflare, Azure, Redis, Heroku, Vercel, Datadog, HuggingFace, Discord, Shopify |
| 🟡 Medium | JWT tokens, Twilio, env file secrets, Slack webhooks |
| 🔵 Low | Test keys, certificates, high-entropy strings |

Plus **Shannon entropy analysis** for detecting unknown secrets by statistical pattern.

## Quick Start

```bash
# Install from source
git clone https://github.com/Manavarya09/secretscan
cd secretscan
./scripts/build.sh && ./scripts/install.sh

# Auto-configure Claude Code
secretscan setup

# That's it — restart Claude Code and you're protected.
```

## What It Looks Like

```bash
$ echo 'ANTHROPIC_API_KEY=sk-ant-api03-...' | secretscan scan

🚨  1 secret found:

  🔴 [CRITICAL]  Anthropic API Key   fingerprint: bbfc6912
             sk-ant-api03-xxxxx…
```

With the hook active, Claude sees:
```
ANTHROPIC_API_KEY=[REDACTED:anthropic_api_key:bbfc6912]
```

## Recovery

Originals are stored **locally** in SQLite — never forwarded anywhere:

```bash
secretscan expand bbfc6912
# → sk-ant-api03-...
```

## Allowlist

False positive? Mark it safe:

```bash
secretscan allow bbfc6912 --reason "This is a test key in the repo"
```

## CLI Reference

```
COMMANDS:
  scan      Scan text, file, or stdin for secrets
  hook      PostToolUse hook mode (reads hook JSON from stdin)
  expand    Retrieve original value by fingerprint
  allow     Add fingerprint to allowlist
  unallow   Remove fingerprint from allowlist
  stats     Show scan statistics
  audit     List recent findings
  patterns  List all 47 built-in patterns
  setup     Auto-install PostToolUse hook into ~/.claude/settings.json

OPTIONS:
  --json        Output as JSON
  --db-path     SQLite path [default: ~/.secretscan/secretscan.db]
  -v, --verbose Verbose logging
```

## Manual Hook Setup

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "secretscan hook" }]
      }
    ]
  }
}
```

## Performance

- **< 2ms** per scan for typical tool outputs
- **Zero network calls** — everything is local
- **< 5MB** binary (release, stripped)

## License

MIT
