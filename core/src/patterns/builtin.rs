//! 50+ built-in secret patterns covering all major providers and formats.

use super::Pattern;
use crate::Severity;
use regex::Regex;

macro_rules! pat {
    ($id:expr, $name:expr, $sev:expr, $re:expr) => {
        Pattern {
            id: $id,
            name: $name,
            severity: $sev,
            regex: Regex::new($re).expect(concat!("invalid regex for ", $id)),
            min_entropy: None,
            context_keywords: &[],
        }
    };
    ($id:expr, $name:expr, $sev:expr, $re:expr, entropy: $e:expr) => {
        Pattern {
            id: $id,
            name: $name,
            severity: $sev,
            regex: Regex::new($re).expect(concat!("invalid regex for ", $id)),
            min_entropy: Some($e),
            context_keywords: &[],
        }
    };
}

pub fn all_patterns() -> Vec<Pattern> {
    vec![
        // ── Anthropic ────────────────────────────────────────────────────────
        pat!(
            "anthropic_api_key",
            "Anthropic API Key",
            Severity::Critical,
            r"sk-ant-[a-zA-Z0-9\-_]{80,}"
        ),

        // ── OpenAI ───────────────────────────────────────────────────────────
        pat!(
            "openai_api_key",
            "OpenAI API Key",
            Severity::Critical,
            r"sk-[a-zA-Z0-9]{48}"
        ),
        pat!(
            "openai_org",
            "OpenAI Organization ID",
            Severity::Medium,
            r"org-[a-zA-Z0-9]{24}"
        ),

        // ── AWS ───────────────────────���────────────────────────────���─────────
        pat!(
            "aws_access_key",
            "AWS Access Key ID",
            Severity::Critical,
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
        ),
        pat!(
            "aws_secret_key",
            "AWS Secret Access Key",
            Severity::Critical,
            r#"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["':\s=]+([A-Za-z0-9/+=]{40})"#,
            entropy: 4.0
        ),
        pat!(
            "aws_session_token",
            "AWS Session Token",
            Severity::High,
            r#"(?i)aws[_\-\s]?session[_\-\s]?token["':\s=]+([A-Za-z0-9/+=]{100,})"#
        ),

        // ── GitHub ───────────────────────────────────────────────────────────
        pat!(
            "github_pat",
            "GitHub Personal Access Token",
            Severity::Critical,
            r"gh[pousr]_[A-Za-z0-9_]{36,255}"
        ),
        pat!(
            "github_oauth",
            "GitHub OAuth Token",
            Severity::High,
            r"gho_[A-Za-z0-9_]{36}"
        ),
        pat!(
            "github_app_token",
            "GitHub App Token",
            Severity::High,
            r"(?:ghu|ghs)_[A-Za-z0-9_]{36}"
        ),

        // ── GitLab ───────────────────────────────────────────���───────────────
        pat!(
            "gitlab_pat",
            "GitLab Personal Access Token",
            Severity::High,
            r"glpat-[a-zA-Z0-9\-_]{20}"
        ),
        pat!(
            "gitlab_pipeline",
            "GitLab Pipeline Trigger Token",
            Severity::Medium,
            r"glptt-[a-f0-9]{40}"
        ),

        // ── Stripe ────────────────────────��─────────────────────────────��────
        pat!(
            "stripe_secret",
            "Stripe Secret Key",
            Severity::Critical,
            r"sk_live_[a-zA-Z0-9]{24,}"
        ),
        pat!(
            "stripe_restricted",
            "Stripe Restricted Key",
            Severity::High,
            r"rk_live_[a-zA-Z0-9]{24,}"
        ),
        pat!(
            "stripe_test",
            "Stripe Test Key",
            Severity::Low,
            r"sk_test_[a-zA-Z0-9]{24,}"
        ),

        // ── Google ─────────────────────────���──────────────────────────���──────
        pat!(
            "google_api_key",
            "Google API Key",
            Severity::High,
            r"AIza[0-9A-Za-z\-_]{35}"
        ),
        pat!(
            "google_oauth",
            "Google OAuth Client Secret",
            Severity::High,
            r"GOCSPX-[a-zA-Z0-9\-_]{28}"
        ),
        pat!(
            "google_service_account",
            "Google Service Account Key",
            Severity::Critical,
            r#""type"\s*:\s*"service_account""#
        ),

        // ── Slack ────────────────────────────────────────────────────────���───
        pat!(
            "slack_bot_token",
            "Slack Bot Token",
            Severity::High,
            r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"
        ),
        pat!(
            "slack_user_token",
            "Slack User Token",
            Severity::High,
            r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}"
        ),
        pat!(
            "slack_webhook",
            "Slack Incoming Webhook",
            Severity::Medium,
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
        ),
        pat!(
            "slack_app_token",
            "Slack App Token",
            Severity::High,
            r"xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]+"
        ),

        // ── npm ────────────────────────────���────────────────────────────��────
        pat!(
            "npm_token",
            "npm Access Token",
            Severity::High,
            r"npm_[a-zA-Z0-9]{36}"
        ),

        // ── SendGrid ────────────────────────────��────────────────────────────
        pat!(
            "sendgrid_api_key",
            "SendGrid API Key",
            Severity::High,
            r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"
        ),

        // ── Twilio ───────────────────────────────────────────────────────────
        pat!(
            "twilio_account_sid",
            "Twilio Account SID",
            Severity::Medium,
            r"AC[a-f0-9]{32}"
        ),
        pat!(
            "twilio_auth_token",
            "Twilio Auth Token",
            Severity::High,
            r"((?i)twilio[_\-\s]?auth[_\-\s]?token[':\s=]+([a-f0-9]{32}))"
        ),

        // ── Cloudflare ───────────────────────────────────────────────────────
        pat!(
            "cloudflare_api_key",
            "Cloudflare API Key",
            Severity::High,
            r"((?i)cloudflare[_\-\s]?(?:api[_\-\s]?)?(?:key|token)[':\s=]+([a-zA-Z0-9_\-]{37,40}))"
        ),
        pat!(
            "cloudflare_global_key",
            "Cloudflare Global API Key",
            Severity::Critical,
            r"[0-9a-f]{37}"
        ),

        // ── Azure ────────────────────────────────────────────────────────────
        pat!(
            "azure_connection_string",
            "Azure Storage Connection String",
            Severity::Critical,
            r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"
        ),
        pat!(
            "azure_sas_token",
            "Azure SAS Token",
            Severity::High,
            r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*?&sig=[A-Za-z0-9%+/=]+"
        ),

        // ── Database URLs ─────────────────────────────────────────────────────
        pat!(
            "postgres_url",
            "PostgreSQL Connection URL with credentials",
            Severity::Critical,
            r"postgres(?:ql)?://[^:]+:[^@\s]{3,}@[^\s]+"
        ),
        pat!(
            "mysql_url",
            "MySQL Connection URL with credentials",
            Severity::Critical,
            r"mysql://[^:]+:[^@\s]{3,}@[^\s]+"
        ),
        pat!(
            "mongodb_url",
            "MongoDB Connection URL with credentials",
            Severity::Critical,
            r"mongodb(?:\+srv)?://[^:]+:[^@\s]{3,}@[^\s]+"
        ),
        pat!(
            "redis_url",
            "Redis URL with password",
            Severity::High,
            r"redis://[^:]*:[^@\s]{3,}@[^\s]+"
        ),

        // ── Private Keys ──────────────────────────────────────────────────────
        pat!(
            "private_key_pem",
            "PEM Private Key",
            Severity::Critical,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?:\s+BLOCK)?-----"
        ),
        pat!(
            "certificate",
            "PEM Certificate",
            Severity::Low,
            r"-----BEGIN CERTIFICATE-----"
        ),

        // ── JWT ─────────────────────────���─────────────────────────────��───────
        pat!(
            "jwt_token",
            "JSON Web Token",
            Severity::Medium,
            r"ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
        ),

        // ── Heroku ───────────────────────────────────────────────────────────��
        pat!(
            "heroku_api_key",
            "Heroku API Key",
            Severity::High,
            r"((?i)heroku[_\-\s]?(?:api[_\-\s]?)?key[':\s=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))"
        ),

        // ── Vercel ──────────────────────────────────���────────────────────���────
        pat!(
            "vercel_token",
            "Vercel Access Token",
            Severity::High,
            r"((?i)vercel[_\-\s]?token[':\s=]+([a-zA-Z0-9]{24}))"
        ),

        // ── Datadog ────────────────────────────────���────────────────────────��─
        pat!(
            "datadog_api_key",
            "Datadog API Key",
            Severity::High,
            r"((?i)(?:datadog|dd)[_\-\s]?(?:api[_\-\s]?)?key[':\s=]+([a-f0-9]{32}))"
        ),

        // ── Mailgun ───────────────────────────────────────────────────────────
        pat!(
            "mailgun_api_key",
            "Mailgun API Key",
            Severity::High,
            r"key-[a-f0-9]{32}"
        ),

        // ── Shopify ─────────────────────��─────────────────────────���───────────
        pat!(
            "shopify_token",
            "Shopify Access Token",
            Severity::High,
            r"shpat_[a-fA-F0-9]{32}"
        ),
        pat!(
            "shopify_shared_secret",
            "Shopify Shared Secret",
            Severity::High,
            r"shpss_[a-fA-F0-9]{32}"
        ),

        // ── Discord ───────────────────────────────────────────────��───────────
        pat!(
            "discord_bot_token",
            "Discord Bot Token",
            Severity::High,
            r"[MN][a-zA-Z0-9\-_]{23,25}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,38}"
        ),
        pat!(
            "discord_webhook",
            "Discord Webhook URL",
            Severity::Medium,
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+"
        ),

        // ── HuggingFace ───────────────────────────────────────���───────────────
        pat!(
            "huggingface_token",
            "HuggingFace Access Token",
            Severity::High,
            r"hf_[a-zA-Z0-9]{34,}"
        ),

        // ── Env-file patterns ─────────────────────────────────────────────────
        pat!(
            "env_secret",
            "Environment Variable with Secret",
            Severity::Medium,
            r#"(?i)(?:SECRET|PASSWORD|PASSWD|PWD|API_KEY|AUTH_TOKEN|PRIVATE_KEY|ACCESS_TOKEN)\s*=\s*["']?([A-Za-z0-9+/=_\-!@#$%^&*]{8,})["']?"#,
            entropy: 3.5
        ),

        // ── Generic credential patterns ───────────────────────────��───────────
        pat!(
            "basic_auth",
            "HTTP Basic Auth Credentials",
            Severity::High,
            r"https?://[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.!@#$%^&*]{4,}@"
        ),
    ]
}
