#ifndef PASSLIB_FFI_H
#define PASSLIB_FFI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque vault type
typedef struct CVault CVault;

// Result codes
typedef enum {
    PassResultSuccess = 0,
    PassResultErrorInvalidPassword = 1,
    PassResultErrorVaultNotFound = 2,
    PassResultErrorVaultExists = 3,
    PassResultErrorEntryNotFound = 4,
    PassResultErrorInvalidInput = 5,
    PassResultErrorUnknown = 99
} PassResult;

// Password entry structure
typedef struct {
    char *id;
    char *website;
    char *url;
    char *username;
    char *password;
    char *notes;             // "" (never NULL) if empty
    char *additional_urls;   // newline-separated, "" (never NULL) if none
    int64_t created_at;
    int64_t updated_at;
    bool has_totp;
    char *totp_code;              // NULL unless has_totp is true
    int64_t totp_seconds_remaining; // -1 unless has_totp is true
} CPasswordEntry;

// List of password entries
typedef struct {
    CPasswordEntry *entries;
    size_t count;
} CPasswordEntryList;

// One previous password from an entry's KDBX4 history
typedef struct {
    char *password;
    int64_t changed_at;
} CPasswordHistoryEntry;

// List of history entries, newest first
typedef struct {
    CPasswordHistoryEntry *entries;
    size_t count;
} CPasswordHistoryList;

// Vault operations
PassResult vault_init(const char *path, const char *password, CVault **vault_out);
PassResult vault_unlock(const char *path, const char *password, CVault **vault_out);
// notes and additional_urls may be NULL (treated as "none"); additional_urls is newline-separated.
PassResult vault_add_entry(CVault *vault, const char *website, const char *url,
                          const char *username, const char *password,
                          const char *notes, const char *additional_urls, char **id_out);
PassResult vault_list_entries(CVault *vault, CPasswordEntryList **list_out);
PassResult vault_get_entry(CVault *vault, const char *id, CPasswordEntry **entry_out);
PassResult vault_get_entry_history(CVault *vault, const char *id, CPasswordHistoryList **list_out);
// password/notes/additional_urls: NULL means "leave unchanged"; website/url/username are always applied.
PassResult vault_update_entry(CVault *vault, const char *id,const char *website,
                             const char *url, const char *username, const char *password,
                             const char *notes, const char *additional_urls);
PassResult vault_delete_entry(CVault *vault, const char*id);

// MFA/TOTP
PassResult vault_set_entry_totp_uri(CVault *vault, const char *id, const char *otpauth_uri);
PassResult vault_clear_entry_totp(CVault *vault, const char *id);

// Cross-device merge, backed by the vault's underlying KDBX4 database merge
// (last-modification-time based — see keepass::Database::merge). created_out /
// updated_out / unchanged_out / deleted_out may each be NULL if the
// caller doesn't need that count.
PassResult vault_merge_from_file(CVault *vault, const char *other_path,
                                 size_t *created_out, size_t *updated_out,
                                 size_t *unchanged_out, size_t *deleted_out);

// Real-time cross-device sync via the local pass-syncd daemon (see
// pass-syncd/README.md and passlib/src/sync.rs). Every vault_add_entry /
// vault_update_entry / vault_delete_entry / vault_set_entry_totp_uri /
// vault_clear_entry_totp / vault_merge_from_file call above already pushes
// its own change automatically — this is the only call needed to pull
// other devices' changes in. Always returns PassResultSuccess unless the
// vault itself is invalid, whether or not pass-syncd is actually reachable
// or this vault has sync set up yet; applied_out (may be NULL) is set to
// how many local entries changed as a result, 0 if none did.
PassResult vault_sync_pull(CVault *vault, size_t *applied_out);

// Joining an existing synced vault from a brand-new device: call right
// after vault_init, before adding anything. vault_check_sync_import_available
// needs no CVault yet (call it to decide whether to show an "import from
// another device?" option on the create-vault screen at all).
// vault_import_from_sync then adopts the discovered sync salt and pulls in
// every entry the mesh currently has; imported_out (may be NULL) is set to
// how many entries were imported, 0 if there was nothing to import.
bool vault_check_sync_import_available(void);
PassResult vault_import_from_sync(CVault *vault, size_t *imported_out);

// The Display message of the most recent error on this thread, or NULL if
// none has occurred yet (e.g. why a call returned PassResultErrorUnknown).
// Caller must free the result with string_free.
char *passlib_last_error_message(void);

// Memory management
void vault_free(CVault *vault);
void string_free(char *s);
void entry_free(CPasswordEntry *entry);
void entry_list_free(CPasswordEntryList *list);
void history_list_free(CPasswordHistoryList *list);

#ifdef __cplusplus
}
#endif

#endif // PASSLIB_FFI_H
