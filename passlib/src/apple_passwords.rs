//! Import from Apple Passwords (iCloud Keychain).
//!
//! Apple offers no API for a third-party app to read the user's saved
//! passwords out of iCloud Keychain, so — like
//! [iCloudBridge](https://github.com/keithvassallomt/icloudbridge) — this
//! works from the CSV file the Passwords app itself exports (macOS:
//! Passwords → File → Export All Passwords to File…; older macOS: Safari →
//! File → Export → Passwords…). That file has the header
//!
//! ```text
//! Title,URL,Username,Password,Notes,OTPAuth
//! ```
//!
//! and one row per *website*: a login saved for several sites (or one
//! Apple shared across several of its own domains) shows up as several
//! rows with the same title/username/password and different URLs. Those
//! rows are folded back into a single entry here, with the extra sites in
//! [`PasswordEntry::additional_urls`] — the same deduplication iCloudBridge
//! applies.
//!
//! Mapping to a [`PasswordEntry`]:
//! - `Title` -> `website`, minus the ` (username)` suffix Apple appends
//!   (falls back to the URL's host when empty)
//! - first `URL` -> `url`, the others -> `additional_urls`
//! - `Username`/`Password`/`Notes` -> the matching fields
//! - `OTPAuth` -> `totp` when it's a TOTP `otpauth://` URI this crate can
//!   parse; anything else is kept verbatim at the end of `notes` rather
//!   than silently dropped
//!
//! Importing the same export twice is a no-op: rows matching an entry the
//! vault already has (same username and password, same site) are skipped.

use crate::entry::PasswordEntry;
use crate::error::{PassError, Result};
use crate::totp;
use crate::vault::Vault;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// The logins parsed from an Apple Passwords CSV export, before touching
/// any vault.
#[derive(Debug, Default)]
pub struct ParsedExport {
    /// One entry per distinct login, rows for the same login on several
    /// sites already folded together.
    pub entries: Vec<PasswordEntry>,
    /// Rows skipped because they had no password (or were otherwise
    /// unusable).
    pub skipped_rows: usize,
}

/// What [`import_csv`]/[`import_csv_file`] did to the vault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppleImportSummary {
    /// IDs of the entries added to the vault, in CSV order.
    pub imported_ids: Vec<String>,
    /// Logins the vault already had (same username, password and site).
    pub already_present: usize,
    /// CSV rows skipped because they had no password.
    pub skipped_rows: usize,
}

impl AppleImportSummary {
    pub fn imported(&self) -> usize {
        self.imported_ids.len()
    }
}

/// Parse an Apple Passwords CSV export.
pub fn parse_csv<R: Read>(reader: R) -> Result<ParsedExport> {
    let mut csv = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(reader);

    let headers = csv
        .headers()
        .map_err(|e| PassError::ImportError(format!("Unreadable CSV header: {e}")))?
        .clone();
    let column = |name: &str| {
        headers
            .iter()
            .position(|h| h.trim_start_matches('\u{feff}').trim().eq_ignore_ascii_case(name))
    };
    let (title_col, url_col, username_col, password_col) =
        match (column("Title"), column("URL"), column("Username"), column("Password")) {
            (Some(t), Some(u), Some(un), Some(p)) => (t, u, un, p),
            _ => {
                return Err(PassError::ImportError(
                    "Not an Apple Passwords export: expected the columns Title, URL, Username, Password"
                        .to_string(),
                ))
            }
        };
    let notes_col = column("Notes");
    let otp_col = column("OTPAuth");

    let mut parsed = ParsedExport::default();
    // (title, username, password) -> index into `parsed.entries`, so rows
    // for the same login on other sites fold into the first one.
    let mut index: HashMap<(String, String, String), usize> = HashMap::new();

    for record in csv.records() {
        let record = record.map_err(|e| PassError::ImportError(format!("Malformed CSV: {e}")))?;
        let field = |col: Option<usize>| col.and_then(|c| record.get(c)).unwrap_or("").trim().to_string();

        let password = record.get(password_col).unwrap_or("").to_string();
        if password.is_empty() {
            parsed.skipped_rows += 1;
            continue;
        }
        let url = field(Some(url_col));
        let username = field(Some(username_col));
        let notes = field(notes_col);
        let otp = field(otp_col);
        let title = clean_title(&field(Some(title_col)), &username, &url);

        let key = (title.to_lowercase(), username.to_lowercase(), password.clone());
        if let Some(&i) = index.get(&key) {
            let existing = &mut parsed.entries[i];
            add_url(existing, url);
            if existing.notes.is_empty() && !notes.is_empty() {
                existing.notes = notes;
            }
            if existing.totp.is_none() {
                apply_otp(existing, &otp);
            }
            continue;
        }

        let mut entry = PasswordEntry::new(title, String::new(), username, password);
        add_url(&mut entry, url);
        entry.notes = notes;
        apply_otp(&mut entry, &otp);

        index.insert(key, parsed.entries.len());
        parsed.entries.push(entry);
    }

    Ok(parsed)
}

/// Parse an Apple Passwords CSV export from disk.
pub fn parse_csv_file<P: AsRef<Path>>(path: P) -> Result<ParsedExport> {
    let path = path.as_ref();
    let file = std::fs::File::open(path)
        .map_err(|e| PassError::ImportError(format!("Cannot open {}: {e}", path.display())))?;
    parse_csv(file)
}

/// Add every login in `parsed` the vault doesn't already have. Does not
/// save — call [`Vault::save`] afterwards, like [`Vault::merge_from_file`].
pub fn import_parsed(vault: &mut Vault, parsed: ParsedExport) -> Result<AppleImportSummary> {
    let mut known: Vec<PasswordEntry> = vault
        .list_entries()?
        .iter()
        .filter_map(|s| vault.get_entry(&s.id).ok())
        .collect();

    let mut summary = AppleImportSummary {
        skipped_rows: parsed.skipped_rows,
        ..Default::default()
    };

    for entry in parsed.entries {
        if known.iter().any(|k| same_login(k, &entry)) {
            summary.already_present += 1;
            continue;
        }
        let id = vault.add_entry(entry.clone())?;
        summary.imported_ids.push(id);
        known.push(entry);
    }

    Ok(summary)
}

/// Parse an Apple Passwords CSV export and add its logins to `vault`. Does
/// not save — see [`import_parsed`].
pub fn import_csv<R: Read>(vault: &mut Vault, reader: R) -> Result<AppleImportSummary> {
    import_parsed(vault, parse_csv(reader)?)
}

/// [`import_csv`] for a file on disk.
pub fn import_csv_file<P: AsRef<Path>>(vault: &mut Vault, path: P) -> Result<AppleImportSummary> {
    import_parsed(vault, parse_csv_file(path)?)
}

/// Apple titles a login "example.com (username)"; drop that suffix since
/// the username has its own field. An empty title falls back to the host.
fn clean_title(title: &str, username: &str, url: &str) -> String {
    let suffix = format!(" ({username})");
    let title = match title.strip_suffix(&suffix) {
        Some(stripped) if !username.is_empty() && !stripped.trim().is_empty() => stripped.trim(),
        _ => title,
    };
    if !title.is_empty() {
        return title.to_string();
    }
    host_of(url).unwrap_or_else(|| url.to_string())
}

fn add_url(entry: &mut PasswordEntry, url: String) {
    if url.is_empty() || entry.all_urls().any(|u| u == url) {
        return;
    }
    if entry.url.is_empty() {
        entry.url = url;
    } else {
        entry.additional_urls.push(url);
    }
}

fn apply_otp(entry: &mut PasswordEntry, otp: &str) {
    if otp.is_empty() {
        return;
    }
    match totp::parse_otpauth_uri(otp) {
        Ok(config) => entry.totp = Some(config),
        Err(_) => {
            if !entry.notes.is_empty() {
                entry.notes.push_str("\n\n");
            }
            entry.notes.push_str("OTPAuth: ");
            entry.notes.push_str(otp);
        }
    }
}

/// Whether `existing` and `imported` are the same login: same username
/// (case-insensitively) and password, for the same site — matched by any
/// shared URL host, or by name when neither has a usable URL.
fn same_login(existing: &PasswordEntry, imported: &PasswordEntry) -> bool {
    if existing.password() != imported.password()
        || !existing.username.trim().eq_ignore_ascii_case(imported.username.trim())
    {
        return false;
    }
    let existing_hosts: Vec<String> = existing.all_urls().filter_map(host_of).collect();
    let imported_hosts: Vec<String> = imported.all_urls().filter_map(host_of).collect();
    if imported_hosts.iter().any(|h| existing_hosts.contains(h)) {
        return true;
    }
    (existing_hosts.is_empty() || imported_hosts.is_empty())
        && existing.website.trim().eq_ignore_ascii_case(imported.website.trim())
}

/// Lowercased host of `url` without a leading `www.`, tolerating a missing
/// scheme ("github.com/login"). `None` for an empty URL.
fn host_of(url: &str) -> Option<String> {
    let rest = url.trim();
    let rest = rest.split_once("://").map_or(rest, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("").to_lowercase();
    let host = host.strip_prefix("www.").map(str::to_string).unwrap_or(host);
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    const EXPORT: &str = "\u{feff}Title,URL,Username,Password,Notes,OTPAuth
github.com (me@example.com),https://github.com/,me@example.com,gh-secret,\"line one
line two, with comma\",otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
apple.com (me@icloud.com),https://appleid.apple.com/,me@icloud.com,apple-secret,,
apple.com (me@icloud.com),https://www.icloud.com/,me@icloud.com,apple-secret,Recovery key,
,https://example.org/login,,\"pa\"\"ss\",,
broken.com (x),https://broken.com/,x,,,
old.com (u),https://old.com/,u,p,,otpauth://hotp/Old?secret=ABC&counter=1
";

    fn temp_vault() -> (Vault, String) {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_path_buf();
        drop(f);
        (Vault::init(&path, "pw").unwrap(), "pw".to_string())
    }

    #[test]
    fn parses_apple_export() {
        let parsed = parse_csv(EXPORT.as_bytes()).unwrap();
        assert_eq!(parsed.skipped_rows, 1);
        assert_eq!(parsed.entries.len(), 4);

        let github = &parsed.entries[0];
        assert_eq!(github.website, "github.com");
        assert_eq!(github.url, "https://github.com/");
        assert_eq!(github.username, "me@example.com");
        assert_eq!(github.password(), "gh-secret");
        assert_eq!(github.notes, "line one\nline two, with comma");
        assert_eq!(github.totp.as_ref().unwrap().secret, "JBSWY3DPEHPK3PXP");

        let apple = &parsed.entries[1];
        assert_eq!(apple.website, "apple.com");
        assert_eq!(apple.url, "https://appleid.apple.com/");
        assert_eq!(apple.additional_urls, vec!["https://www.icloud.com/".to_string()]);
        assert_eq!(apple.notes, "Recovery key");

        let untitled = &parsed.entries[2];
        assert_eq!(untitled.website, "example.org");
        assert_eq!(untitled.password(), "pa\"ss");

        let hotp = &parsed.entries[3];
        assert!(hotp.totp.is_none());
        assert!(hotp.notes.contains("otpauth://hotp/Old"));
    }

    #[test]
    fn rejects_non_apple_csv() {
        let err = parse_csv("name,login_uri\na,b\n".as_bytes()).unwrap_err();
        assert!(matches!(err, PassError::ImportError(_)));
    }

    #[test]
    fn import_is_idempotent() {
        let (mut vault, pw) = temp_vault();

        let first = import_csv(&mut vault, EXPORT.as_bytes()).unwrap();
        assert_eq!(first.imported(), 4);
        assert_eq!(first.already_present, 0);
        vault.save(&pw).unwrap();
        assert_eq!(vault.len(), 4);

        let second = import_csv(&mut vault, EXPORT.as_bytes()).unwrap();
        assert_eq!(second.imported(), 0);
        assert_eq!(second.already_present, 4);
        assert_eq!(vault.len(), 4);

        let github = vault.get_entry(&first.imported_ids[0]).unwrap();
        assert!(github.totp.is_some());
    }

    #[test]
    fn existing_entry_on_same_host_is_not_duplicated() {
        let (mut vault, _) = temp_vault();
        vault
            .add_entry(PasswordEntry::new(
                "GitHub".to_string(),
                "https://www.github.com/login".to_string(),
                "ME@example.com".to_string(),
                "gh-secret".to_string(),
            ))
            .unwrap();

        let summary = import_csv(&mut vault, EXPORT.as_bytes()).unwrap();
        assert_eq!(summary.already_present, 1);
        assert_eq!(summary.imported(), 3);
    }

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("https://www.GitHub.com:443/login?x=1").as_deref(), Some("github.com"));
        assert_eq!(host_of("user@example.org/path").as_deref(), Some("example.org"));
        assert_eq!(host_of("  "), None);
    }
}
