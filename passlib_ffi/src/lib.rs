use libc::{c_char, size_t};
use passlib::{PasswordEntry, Vault};
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::slice;

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
        Err(_) => PassResult::ErrorUnknown,
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
        Err(_) => PassResult::ErrorUnknown,
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
            if let Err(_) = vault_ref.save(&cvault.master_password) {
                return PassResult::ErrorUnknown;
            }
            if !id_out.is_null() {
                *id_out = to_c_string(&id);
            }
            PassResult::Success
        }
        Err(_) => PassResult::ErrorUnknown,
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
                    c_entries.push(CPasswordEntry {
                        id: to_c_string(&entry.id),
                        website: to_c_string(&entry.website),
                        url: to_c_string(&entry.url),
                        username: to_c_string(&entry.username),
                        password: to_c_string(entry.password()),
                        created_at: entry.created_at.timestamp(),
                        updated_at: entry.updated_at.timestamp(),
                    });
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
        Err(_) => PassResult::ErrorUnknown,
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
            let c_entry = Box::new(CPasswordEntry {
                id: to_c_string(&entry.id),
                website: to_c_string(&entry.website),
                url: to_c_string(&entry.url),
                username: to_c_string(&entry.username),
                password: to_c_string(entry.password()),
                created_at: entry.created_at.timestamp(),
                updated_at: entry.updated_at.timestamp(),
            });
            *entry_out = Box::into_raw(c_entry);
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(_) => PassResult::ErrorUnknown,
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
            if let Err(_) = vault_ref.save(&cvault.master_password) {
                return PassResult::ErrorUnknown;
            }
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(_) => PassResult::ErrorUnknown,
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
            if let Err(_) = vault_ref.save(&cvault.master_password) {
                return PassResult::ErrorUnknown;
            }
            PassResult::Success
        }
        Err(passlib::PassError::EntryNotFound(_)) => PassResult::ErrorEntryNotFound,
        Err(_) => PassResult::ErrorUnknown,
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
            }
            Vec::from_raw_parts(list.entries, list.count, list.count);
        }
    }
}
