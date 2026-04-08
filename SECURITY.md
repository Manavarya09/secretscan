# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |
| < latest| :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in SecretScan, please report it responsibly.

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email: Create a private security advisory on this repository
2. Go to **Security** → **Advisories** → **New draft security advisory**
3. Provide:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix/Patch**: Within 2 weeks for critical issues

### What to Expect

- We will acknowledge receipt of your report
- We will investigate and validate the issue
- We will work on a fix and coordinate disclosure
- We will credit you in the release notes (unless you prefer anonymity)

## Security Best Practices

When using SecretScan:
- Always run scans before committing code
- Keep SecretScan updated to the latest version
- Review scan results carefully — false negatives are possible
- Use the PostToolUse hook for automatic scanning

## Scope

This policy covers the SecretScan codebase and official distribution channels only.
