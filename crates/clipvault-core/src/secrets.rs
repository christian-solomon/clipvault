//! Spots copies that look like credentials, so they can be kept in memory
//! only instead of being written to the history database.
//!
//! Known token formats are matched by pattern. Anything else has to pass a
//! deliberately conservative randomness test: a false positive only means a
//! clip expires from the list after a few minutes unless kept, while a false
//! negative writes a credential to disk. The test still has to leave commit
//! hashes, UUIDs, URLs and paths alone, or the feature would be noise.

use regex::RegexSet;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    PrivateKey,
    AwsAccessKey,
    GitHubToken,
    GitLabToken,
    SlackToken,
    SlackWebhook,
    StripeKey,
    GoogleApiKey,
    AnthropicKey,
    OpenAiKey,
    Jwt,
    ConnectionString,
    UrlCredentials,
    RandomToken,
}

impl Kind {
    pub fn describe(self) -> &'static str {
        match self {
            Kind::PrivateKey => "private key",
            Kind::AwsAccessKey => "AWS access key",
            Kind::GitHubToken => "GitHub token",
            Kind::GitLabToken => "GitLab token",
            Kind::SlackToken => "Slack token",
            Kind::SlackWebhook => "Slack webhook",
            Kind::StripeKey => "Stripe key",
            Kind::GoogleApiKey => "Google API key",
            Kind::AnthropicKey => "Anthropic API key",
            Kind::OpenAiKey => "OpenAI API key",
            Kind::Jwt => "JWT",
            Kind::ConnectionString => "connection string with a key",
            Kind::UrlCredentials => "URL with a password",
            Kind::RandomToken => "random-looking token",
        }
    }
}

/// Pattern order is priority order: the first match names the kind, which
/// matters where one format is a prefix of another (`sk-ant-` before `sk-`).
const PATTERNS: &[(Kind, &str)] = &[
    (Kind::PrivateKey, r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----"),
    (Kind::AwsAccessKey, r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    (Kind::GitHubToken, r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    (Kind::GitLabToken, r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    (Kind::SlackToken, r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"),
    (Kind::SlackWebhook, r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    (Kind::StripeKey, r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    (Kind::GoogleApiKey, r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    (Kind::AnthropicKey, r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    (Kind::OpenAiKey, r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    (Kind::Jwt, r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    (Kind::ConnectionString, r"(?i)\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)=[A-Za-z0-9+/=%]{20,}"),
    // scheme://user:password@host, with a non-empty password.
    (Kind::UrlCredentials, r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:[^\s/@]+@[^\s/]+"),
];

static SET: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new(PATTERNS.iter().map(|(_, p)| *p)).expect("valid patterns"));

/// Returns what the text looks like, or `None` for ordinary content.
pub fn detect(text: &str) -> Option<Kind> {
    if let Some(i) = SET.matches(text).into_iter().next() {
        return Some(PATTERNS[i].0);
    }
    random_token(text).then_some(Kind::RandomToken)
}

/// A single token of password length whose characters look drawn at random.
///
/// Requires three of the four character classes, which rules out hex hashes
/// and UUIDs (no upper case), and an empirical entropy of at least 4.3 bits
/// per character, which rules out words and camelCase identifiers. URLs and
/// paths are skipped outright; their structure says what they are.
fn random_token(text: &str) -> bool {
    let t = text.trim();
    let len = t.chars().count();
    if !(20..=128).contains(&len) || t.chars().any(char::is_whitespace) {
        return false;
    }
    if t.contains("://") || t.starts_with(['/', '~', '.']) || t.contains('\\') {
        return false;
    }
    let classes = [
        t.chars().any(|c| c.is_ascii_lowercase()),
        t.chars().any(|c| c.is_ascii_uppercase()),
        t.chars().any(|c| c.is_ascii_digit()),
        t.chars().any(|c| c.is_ascii_punctuation()),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    classes >= 3 && entropy(t) >= 4.3
}

/// Shannon entropy of the string's own character distribution, in bits.
fn entropy(t: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut n = 0usize;
    for c in t.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        n += 1;
    }
    counts
        .values()
        .map(|&k| {
            let p = k as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures are assembled at runtime so that scanners reading this file do
    // not flag it; none of them is a live credential.
    fn j(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn known_formats_are_recognised() {
        let cases: Vec<(String, Kind)> = vec![
            (j(&["-----BEGIN OPENSSH ", "PRIVATE KEY-----\nb3Bl\n"]), Kind::PrivateKey),
            (j(&["-----BEGIN RSA ", "PRIVATE KEY-----"]), Kind::PrivateKey),
            (j(&["-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"]), Kind::PrivateKey),
            (j(&["aws_access_key_id = AKIA", "IOSFODNN7EXAMPLE"]), Kind::AwsAccessKey),
            (j(&["ghp_", &"a1B2".repeat(9)]), Kind::GitHubToken),
            (j(&["github_pat_", &"A1b2_".repeat(10)]), Kind::GitHubToken),
            (j(&["glpat-", "xxxxxxxxxxxxxxxxxxxx"]), Kind::GitLabToken),
            (j(&["xoxb-", "123456789012-abcdefghij"]), Kind::SlackToken),
            (j(&["https://hooks.slack.com/services/", "T0001/B0002/abcdef123"]), Kind::SlackWebhook),
            (j(&["sk_live_", "4eC39HqLyjWDarjtT1zdp7dc"]), Kind::StripeKey),
            (j(&["AIza", "SyA-1234567890abcdefghijklmnopqrstu"]), Kind::GoogleApiKey),
            (j(&["sk-ant-", "api03-abcdefghijklmnopqrstuvwxyz"]), Kind::AnthropicKey),
            (j(&["sk-proj-", "abcdefghijklmnopqrstuvwxyz012345"]), Kind::OpenAiKey),
            (
                j(&["eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".dozjgNryP4J3jVmNHl0w5N"]),
                Kind::Jwt,
            ),
            (
                j(&["DefaultEndpointsProtocol=https;AccountName=x;", "AccountKey=", &"Ab3+".repeat(10)]),
                Kind::ConnectionString,
            ),
            (j(&["postgres://app:", "s3cr3t@db.internal:5432/app"]), Kind::UrlCredentials),
        ];
        for (text, kind) in cases {
            assert_eq!(detect(&text), Some(kind), "{text}");
        }
    }

    #[test]
    fn a_secret_inside_surrounding_text_is_still_found() {
        let text = j(&["export AWS_ACCESS_KEY_ID=AKIA", "IOSFODNN7EXAMPLE # prod"]);
        assert_eq!(detect(&text), Some(Kind::AwsAccessKey));
    }

    #[test]
    fn generated_passwords_are_caught() {
        for pw in ["xK9#mP2$vL7@nQ4&wR8!", "Tz8vQ2mL9pX4kW7nR3sB6yF1", "a8F$k2!Lq9@Zw4#Xv7&Mn3"] {
            assert_eq!(detect(pw), Some(Kind::RandomToken), "{pw}");
        }
    }

    #[test]
    fn ordinary_content_is_left_alone() {
        for text in [
            "hello world",
            "The quick brown fox jumps over the lazy dog.",
            "d2a4fb6ded7c470be25d1541281da3882495b65b",
            "550e8400-e29b-41d4-a716-446655440000",
            "https://github.com/christian-solomon/clipvault/pull/12",
            "https://example.com/Path/To/Some-File_v2.html?ref=Docs123",
            "/home/user/projects/clipvault/crates/clipvault-core/src/Store.rs",
            "~/Downloads/Screenshot_2026-11-16_12-58-01.png",
            "getUserAccountSettingsByIdentifier2024",
            "SELECT id, preview FROM entries WHERE pinned = 1",
            "user@example.com",
            "https://user@example.com/repo.git",
            "ssh deploy@10.0.4.12 -i ~/.ssh/prod",
            "AKIA",
            "sk-short",
            "2026-11-16T12:58:01.123456789Z",
            "C:\\Users\\Someone\\Documents\\Report-Final-v3.docx",
        ] {
            assert_eq!(detect(text), None, "{text}");
        }
    }

    #[test]
    fn entropy_is_measured_per_character() {
        assert_eq!(entropy("aaaa"), 0.0);
        assert!((entropy("abcd") - 2.0).abs() < 1e-9);
    }
}
