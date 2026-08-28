use libc::{c_char, size_t};
use passlib::{PassError, PasswordEntry, Vault};
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::slice;

thread_local! {
    // The `Display` text of the most recent `PassError` on this thread, for
    // callers (the Swift/App layer) that want to show *why* a call returned
    // `PassResultErrorUnknown` instead of just the opaque code — mirrors
    // what the CLI already shows via `anyhow`'s error context.
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn set_last_error(err: &PassError) {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = Some(err.to_string()));
}

/// The `Display` message of the most recent error on this thread, or NULL
/// if none has occurred yet. Caller must free the result with `string_free`.
///
/// # Safety
/// - The returned pointer, if non-NULL, must be freed with `string_free`.
#[no_mangle]
pub unsafe extern "C" fn passlib_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
        Some(msg) => to_c_string(msg),
        None => std::ptr::null_mut(),
    })
}

// Opaque pointer type for Vault
pub struct CVault {
    vault: Option<Vault>,
    master_password: String,
}

/// Result codes for FFI functions
#[repr(C)]
pub enum PassResult {
    Success = 0,
    ErrorInvalidPassword = 1,
    ErrorVaultNotFound = 2,
    ErrorVaultExists = 3,
    ErrorEntryNotFound = 4,
    ErrorInvalidInput = 5,
    ErrorUnknown = 99,
}

/// C-compatible password entry structure
#[repr(C)]
pub struct CPasswordEntry {
    pub id: *mut c_char,
    pub website: *mut c_char,
    pub url: *mut c_char,
    pub username: *mut c_char,
    pub password: *mut c_char,
    pub created_at: i64,      // Unix timestamp
    pub updated_at: i64,      // Unix timestamp
    pub has_totp: bool,
    pub totp_code: *mut c_char,       // NULL unless has_totp is true
    pub totp_seconds_remaining: i64,  // -1 unless has_totp is true
}

/// C-compatible list of password entries
#[repr(C)]
pub struct CPasswordEntryList {
    pub entries: *mut CPasswordEntry,
    pub count: size_t,
}

// Helper function to convert Rust string to C string
fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).unwrap().into_raw()
}

// Helper function to convert C string to Rust string
unsafe fn from_c_string(s: *const c_char) -> Result<String, PassResult> {
    if s.is_null() {
        return Err(PassResult::ErrorInvalidInput);
    }
    CStr::from_ptr(s)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| PassResult::ErrorInvalidInput)
}

/// Initialize a new vault
///
/// # Safety
/// - path and password must be valid C strings
/// - vault_out must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn vault_init(
    path: *const c_char,
    password: *const c_char,
    vault_out: *mut *mut CVault,
) -> PassResult {
    let path_str = match from_c_string(path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let password_str = match from_c_string(password) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let vault_path = PathBuf::from(&path_str);
    
    if vault_path.exists() {
        return PassResult::ErrorVaultExists;
    }

    match Vault::init(&vault_path, &password_str) {
        Ok(vault) => {
            let cvault = Box::new(CVault {
                vault: Some(vault),
                master_password: password_str,
            });
            *vault_out = Box::into_raw(cvault);
            PassResult::Success
        }
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Unlock an existing vault
///
/// # Safety
/// - path and password must be valid C strings
/// - vault_out must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn vault_unlock(
    path: *const c_char,
    password: *const c_char,
    vault_out: *mut *mut CVault,
) -> PassResult {
    let path_str = match from_c_string(path) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let password_str = match from_c_string(password) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let vault_path = PathBuf::from(&path_str);

    match Vault::unlock(&vault_path, &password_str) {
        Ok(vault) => {
            let cvault = Box::new(CVault {
                vault: Some(vault),
                master_password: password_str,
            });
            *vault_out = Box::into_raw(cvault);
            PassResult::Success
        }
        Err(passlib::PassError::InvalidPassword) => PassResult::ErrorInvalidPassword,
        Err(passlib::PassError::VaultNotFound(_)) => PassResult::ErrorVaultNotFound,
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Add a new password entry
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - All string pointers must be valid C strings
#[no_mangle]
pub unsafe extern "C" fn vault_add_entry(
    vault: *mut CVault,
    website: *const c_char,
    url: *const c_char,
    username: *const c_char,
    password: *const c_char,
    id_out: *mut *mut c_char,
) -> PassResult {
    if vault.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &mut *vault;
    let vault_ref = match cvault.vault.as_mut() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    let website_str = match from_c_string(website) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let url_str = match from_c_string(url) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let username_str = match from_c_string(username) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let password_str = match from_c_string(password) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let entry = PasswordEntry::new(website_str, url_str, username_str, password_str);
    let id = entry.id.clone();

    match vault_ref.add_entry(entry) {
        Ok(_) => {
            if let Err(e) = vault_ref.save(&cvault.master_password) {
                set_last_error(&e);
                return PassResult::ErrorUnknown;
            }
            if !id_out.is_null() {
                *id_out = to_c_string(&id);
            }
            PassResult::Success
        }
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

// Build a CPasswordEntry, including the current TOTP code if the entry has
// an MFA secret attached. Shared by vault_list_entries and vault_get_entry
// so both surface the same fields the same way.
fn build_c_entry(entry: &PasswordEntry) -> CPasswordEntry {
    let (has_totp, totp_code, totp_seconds_remaining) = match &entry.totp {
        Some(totp) => {
            let now = chrono::Utc::now();
            match passlib::totp::generate_code(totp, now) {
                Ok(code) => (
                    true,
                    to_c_string(&code),
                    passlib::totp::seconds_remaining(totp, now) as i64,
                ),
                Err(_) => (true, std::ptr::null_mut(), -1),
            }
        }
        None => (false, std::ptr::null_mut(), -1),
    };

    CPasswordEntry {
        id: to_c_string(&entry.id),
        website: to_c_string(&entry.website),
        url: to_c_string(&entry.url),
        username: to_c_string(&entry.username),
        password: to_c_string(entry.password()),
        created_at: entry.created_at.timestamp(),
        updated_at: entry.updated_at.timestamp(),
        has_totp,
        totp_code,
        totp_seconds_remaining,
    }
}

/// List all password entries
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - list_out must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn vault_list_entries(
    vault: *mut CVault,
    list_out: *mut *mut CPasswordEntryList,
) -> PassResult {
    if vault.is_null() || list_out.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &*vault;
    let vault_ref = match cvault.vault.as_ref() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    match vault_ref.list_entries() {
        Ok(entries) => {
            let count = entries.len();
            let mut c_entries = Vec::with_capacity(count);

            for summary in entries {
                // Get full entry to access password
                if let Ok(entry) = vault_ref.get_entry(&summary.id) {
                    c_entries.push(build_c_entry(&entry));
                }
            }

            let list = Box::new(CPasswordEntryList {
                entries: c_entries.as_mut_ptr(),
                count: c_entries.len(),
            });
            std::mem::forget(c_entries); // Prevent deallocation
            *list_out = Box::into_raw(list);
            PassResult::Success
        }
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Get a specific password entry by ID
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - id must be a valid C string
/// - entry_out must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn vault_get_entry(
    vault: *mut CVault,
    id: *const c_char,
    entry_out: *mut *mut CPasswordEntry,
) -> PassResult {
    if vault.is_null() || entry_out.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &*vault;
    let vault_ref = match cvault.vault.as_ref() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    let id_str = match from_c_string(id) {
        Ok(s) => s,
        Err(e) => return e,
    };

    match vault_ref.get_entry(&id_str) {
        Ok(entry) => {
            let c_entry = Box::new(build_c_entry(&entry));
            *entry_out = Box::into_raw(c_entry);
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Update a password entry
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - All string pointers must be valid C strings
#[no_mangle]
pub unsafe extern "C" fn vault_update_entry(
    vault: *mut CVault,
    id: *const c_char,
    website: *const c_char,
    url: *const c_char,
    username: *const c_char,
    password: *const c_char, // NULL if not updating password
) -> PassResult {
    if vault.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &mut *vault;
    let vault_ref = match cvault.vault.as_mut() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    let id_str = match from_c_string(id) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let website_str = match from_c_string(website) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let url_str = match from_c_string(url) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let username_str = match from_c_string(username) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let password_opt = if password.is_null() {
        None
    } else {
        match from_c_string(password) {
            Ok(s) => Some(s),
            Err(e) => return e,
        }
    };

    match vault_ref.update_entry(
        &id_str,
        Some(website_str),
        Some(url_str),
        Some(username_str),
        password_opt,
    ) {
        Ok(_) => {
            if let Err(e) = vault_ref.save(&cvault.master_password) {
                set_last_error(&e);
                return PassResult::ErrorUnknown;
            }
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Delete a password entry
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - id must be a valid C string
#[no_mangle]
pub unsafe extern "C" fn vault_delete_entry(
    vault: *mut CVault,
    id: *const c_char,
) -> PassResult {
    if vault.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &mut *vault;
    let vault_ref = match cvault.vault.as_mut() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    let id_str = match from_c_string(id) {
        Ok(s) => s,
        Err(e) => return e,
    };

    match vault_ref.delete_entry(&id_str) {
        Ok(_) => {
            if let Err(e) = vault_ref.save(&cvault.master_password) {
                set_last_error(&e);
                return PassResult::ErrorUnknown;
            }
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Attach an MFA/TOTP secret to an entry, parsed from an otpauth:// URI
/// (the kind encoded by a service's 2FA setup QR code). Decoding a QR
/// code image into that URI is left to the caller (e.g. via a
/// platform-native image/QR library); this only handles the URI itself.
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - id and otpauth_uri must be valid C strings
#[no_mangle]
pub unsafe extern "C" fn vault_set_entry_totp_uri(
    vault: *mut CVault,
    id: *const c_char,
    otpauth_uri: *const c_char,
) -> PassResult {
    if vault.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &mut *vault;
    let vault_ref = match cvault.vault.as_mut() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    let id_str = match from_c_string(id) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let uri_str = match from_c_string(otpauth_uri) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let totp = match passlib::totp::parse_otpauth_uri(&uri_str) {
        Ok(t) => t,
        Err(_) => return PassResult::ErrorInvalidInput,
    };

    match vault_ref.set_entry_totp(&id_str, totp) {
        Ok(_) => {
            if let Err(e) = vault_ref.save(&cvault.master_password) {
                set_last_error(&e);
                return PassResult::ErrorUnknown;
            }
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Remove the MFA/TOTP secret from an entry, if any
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - id must be a valid C string
#[no_mangle]
pub unsafe extern "C" fn vault_clear_entry_totp(vault: *mut CVault, id: *const c_char) -> PassResult {
    if vault.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &mut *vault;
    let vault_ref = match cvault.vault.as_mut() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    let id_str = match from_c_string(id) {
        Ok(s) => s,
        Err(e) => return e,
    };

    match vault_ref.clear_entry_totp(&id_str) {
        Ok(_) => {
            if let Err(e) = vault_ref.save(&cvault.master_password) {
                set_last_error(&e);
                return PassResult::ErrorUnknown;
            }
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Merge another copy of this vault (e.g. one synced via Nextcloud) into
/// the currently open vault and save the result. `*_out` parameters may be
/// NULL if the caller doesn't need the merge counts.
///
/// # Safety
/// - vault must be a valid CVault pointer
/// - other_path must be a valid C string
/// - each non-NULL `*_out` pointer must be a valid `size_t` pointer
#[no_mangle]
pub unsafe extern "C" fn vault_merge_from_file(
    vault: *mut CVault,
    other_path: *const c_char,
    created_out: *mut size_t,
    updated_out: *mut size_t,
    unchanged_out: *mut size_t,
    deleted_out: *mut size_t,
) -> PassResult {
    if vault.is_null() {
        return PassResult::ErrorInvalidInput;
    }

    let cvault = &mut *vault;
    let vault_ref = match cvault.vault.as_mut() {
        Some(v) => v,
        None => return PassResult::ErrorUnknown,
    };

    let other_path_str = match from_c_string(other_path) {
        Ok(s) => s,
        Err(e) => return e,
    };

    match vault_ref.merge_from_file(&other_path_str, &cvault.master_password) {
        Ok(summary) => {
            if let Err(e) = vault_ref.save(&cvault.master_password) {
                set_last_error(&e);
                return PassResult::ErrorUnknown;
            }
            if !created_out.is_null() {
                *created_out = summary.created;
            }
            if !updated_out.is_null() {
                *updated_out = summary.updated;
            }
            if !unchanged_out.is_null() {
                *unchanged_out = summary.unchanged;
            }
            if !deleted_out.is_null() {
                *deleted_out = summary.deleted;
            }
            PassResult::Success
        }
        Err(passlib::PassError::VaultNotFound(_)) => PassResult::ErrorVaultNotFound,
        Err(passlib::PassError::InvalidPassword) => PassResult::ErrorInvalidPassword,
        Err(e) => {
            set_last_error(&e);
            PassResult::ErrorUnknown
        }
    }
}

/// Free a vault instance
///
/// # Safety
/// - vault must be a valid CVault pointer or NULL
#[no_mangle]
pub unsafe extern "C" fn vault_free(vault: *mut CVault) {
    if !vault.is_null() {
        let _ = Box::from_raw(vault);
    }
}

/// Free a C string
///
/// # Safety
/// - s must be a valid C string allocated by this library or NULL
#[no_mangle]
pub unsafe extern "C" fn string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

/// Free a password entry
///
/// # Safety
/// - entry must be a valid CPasswordEntry pointer or NULL
#[no_mangle]
pub unsafe extern "C" fn entry_free(entry: *mut CPasswordEntry) {
    if !entry.is_null() {
        let entry = Box::from_raw(entry);
        string_free(entry.id);
        string_free(entry.website);
        string_free(entry.url);
        string_free(entry.username);
        string_free(entry.password);
        string_free(entry.totp_code);
    }
}

/// Free a password entry list
///
/// # Safety
/// - list must be a valid CPasswordEntryList pointer or NULL
#[no_mangle]
pub unsafe extern "C" fn entry_list_free(list: *mut CPasswordEntryList) {
    if !list.is_null() {
        let list = Box::from_raw(list);
        if !list.entries.is_null() {
            let entries = slice::from_raw_parts_mut(list.entries, list.count);
            for entry in entries {
                string_free(entry.id);
                string_free(entry.website);
                string_free(entry.url);
                string_free(entry.username);
                string_free(entry.password);
                string_free(entry.totp_code);
            }
            Vec::from_raw_parts(list.entries, list.count, list.count);
        }
    }
}
