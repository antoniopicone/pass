//! TOTP (RFC 6238) code generation and `otpauth://` URI parsing, for
//! storing MFA/2FA secrets (the kind exported as a QR code by GitHub,
//! Google, etc.) alongside a vault entry.
//!
//! The secret is kept as its original base32 text (as encoded in the QR
//! code) rather than raw bytes, since that's how every authenticator app
//! stores and displays it and it round-trips through JSON/vault storage
//! without any extra encoding step. It's only base32-decoded transiently
//! when a code needs to be generated.

use crate::error::{PassError, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// HMAC algorithm backing the TOTP code. SHA1 is by far the most common in
/// the wild (it's what most services' QR codes still use) despite the name;
/// TOTP's security comes from the shared secret, not from SHA1 collision
/// resistance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(PassError::TotpError(format!("Unsupported TOTP algorithm: {other}"))),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// A TOTP secret and the parameters needed to generate codes from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32-encoded shared secret, exactly as it appears in the
    /// `otpauth://` URI / QR code.
    pub secret: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl TotpConfig {
    /// A compact, deterministic string of every field that affects the
    /// generated codes or the label shown to the user. Used by
    /// [`crate::entry::PasswordEntry::fingerprint`] to detect changes for
    /// merge conflict resolution.
    pub(crate) fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.secret,
            self.algorithm.as_str(),
            self.digits,
            self.period,
            self.issuer.as_deref().unwrap_or(""),
            self.account.as_deref().unwrap_or(""),
        )
    }
}

/// Generate the current TOTP code for `config` at time `at`.
pub fn generate_code(config: &TotpConfig, at: DateTime<Utc>) -> Result<String> {
    let secret_bytes = decode_secret(&config.secret)?;
    let counter = (at.timestamp().max(0) as u64) / config.period;
    let code = generate_code_from_bytes(&secret_bytes, config.algorithm, config.digits, counter);
    Ok(format!("{:0width$}", code, width = config.digits as usize))
}

/// Seconds remaining until the code for `config` changes, at time `at`.
pub fn seconds_remaining(config: &TotpConfig, at: DateTime<Utc>) -> u64 {
    let elapsed = (at.timestamp().max(0) as u64) % config.period;
    config.period - elapsed
}

fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned.to_ascii_uppercase())
        .ok_or_else(|| PassError::TotpError("TOTP secret is not valid base32".to_string()))
}

/// RFC 4226 HOTP value, generalized to RFC 6238's choice of hash algorithm.
fn generate_code_from_bytes(secret: &[u8], algorithm: TotpAlgorithm, digits: u32, counter: u64) -> u32 {
    let counter_bytes = counter.to_be_bytes();
    let hash: Vec<u8> = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts keys of any length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts keys of any length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret).expect("HMAC accepts keys of any length");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation (RFC 4226 section 5.3).
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    binary % 10u32.pow(digits)
}

/// Parse an `otpauth://totp/...` URI, as encoded in a QR code exported by a
/// service's MFA setup page, into a [`TotpConfig`]. HOTP (counter-based)
/// URIs are not supported since virtually every real-world service uses
/// TOTP.
pub fn parse_otpauth_uri(uri: &str) -> Result<TotpConfig> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| PassError::TotpError("Not a TOTP otpauth:// URI".to_string()))?;

    let (label, query) = rest
        .split_once('?')
        .ok_or_else(|| PassError::TotpError("Malformed otpauth URI: missing parameters".to_string()))?;

    let label = percent_decode(label);
    let (issuer_from_label, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.trim().to_string()), account.trim().to_string()),
        None => (None, label.trim().to_string()),
    };

    let mut secret = None;
    let mut issuer = issuer_from_label;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits = 6u32;
    let mut period = 30u64;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(raw_value);
        match key {
            "secret" => secret = Some(value),
            "issuer" => issuer = Some(value),
            "algorithm" => algorithm = TotpAlgorithm::parse(&value)?,
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| PassError::TotpError(format!("Invalid digits value: {value}")))?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| PassError::TotpError(format!("Invalid period value: {value}")))?
            }
            _ => {}
        }
    }

    let secret = secret.ok_or_else(|| PassError::TotpError("otpauth URI is missing the secret parameter".to_string()))?;
    if period == 0 {
        return Err(PassError::TotpError("TOTP period must be greater than zero".to_string()));
    }

    Ok(TotpConfig {
        secret,
        algorithm,
        digits,
        period,
        issuer,
        account: Some(account),
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B official test vectors: 20-byte ASCII secret,
    /// SHA1, 8-digit codes, 30s step, T0 = 0.
    #[test]
    fn rfc6238_sha1_test_vectors() {
        let secret = b"12345678901234567890";
        let cases: &[(u64, u32)] = &[
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
        ];

        for &(unix_time, expected) in cases {
            let counter = unix_time / 30;
            let code = generate_code_from_bytes(secret, TotpAlgorithm::Sha1, 8, counter);
            assert_eq!(code, expected, "mismatch at unix_time={unix_time}");
        }
    }

    #[test]
    fn generate_code_matches_config_and_produces_zero_padded_digits() {
        let config = TotpConfig {
            secret: base32::encode(base32::Alphabet::Rfc4648 { padding: false }, b"12345678901234567890"),
            algorithm: TotpAlgorithm::Sha1,
            digits: 8,
            period: 30,
            issuer: None,
            account: None,
        };

        let at = DateTime::from_timestamp(59, 0).unwrap();
        let code = generate_code(&config, at).unwrap();
        assert_eq!(code, "94287082");
    }

    #[test]
    fn seconds_remaining_counts_down_within_the_period() {
        let config = TotpConfig {
            secret: "AAAA".to_string(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        };

        assert_eq!(seconds_remaining(&config, DateTime::from_timestamp(0, 0).unwrap()), 30);
        assert_eq!(seconds_remaining(&config, DateTime::from_timestamp(29, 0).unwrap()), 1);
        assert_eq!(seconds_remaining(&config, DateTime::from_timestamp(30, 0).unwrap()), 30);
    }

    #[test]
    fn parse_otpauth_uri_extracts_all_fields() {
        let uri = "otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        let config = parse_otpauth_uri(uri).unwrap();

        assert_eq!(config.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(config.issuer.as_deref(), Some("GitHub"));
        assert_eq!(config.account.as_deref(), Some("me@example.com"));
        assert_eq!(config.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
    }

    #[test]
    fn parse_otpauth_uri_falls_back_to_defaults_and_label_without_issuer() {
        let uri = "otpauth://totp/me@example.com?secret=JBSWY3DPEHPK3PXP";
        let config = parse_otpauth_uri(uri).unwrap();

        assert_eq!(config.issuer, None);
        assert_eq!(config.account.as_deref(), Some("me@example.com"));
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
    }

    #[test]
    fn parse_otpauth_uri_rejects_non_totp_and_missing_secret() {
        assert!(parse_otpauth_uri("otpauth://hotp/me?secret=AAAA").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/me?issuer=X").is_err());
    }
}
