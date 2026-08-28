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

// Vault operations
PassResult vault_init(const char *path, const char *password, CVault **vault_out);
PassResult vault_unlock(const char *path, const char *password, CVault **vault_out);
PassResult vault_add_entry(CVault *vault, const char *website, const char *url, 
                          const char *username, const char *password, char **id_out);
PassResult vault_list_entries(CVault *vault, CPasswordEntryList **list_out);
PassResult vault_get_entry(CVault *vault, const char *id, CPasswordEntry **entry_out);
PassResult vault_update_entry(CVault *vault, const char *id,const char *website, 
                             const char *url, const char *username, const char *password);
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

// The Display message of the most recent error on this thread, or NULL if
// none has occurred yet (e.g. why a call returned PassResultErrorUnknown).
// Caller must free the result with string_free.
char *passlib_last_error_message(void);

// Memory management
void vault_free(CVault *vault);
void string_free(char *s);
void entry_free(CPasswordEntry *entry);
void entry_list_free(CPasswordEntryList *list);

#ifdef __cplusplus
}
#endif

#endif // PASSLIB_FFI_H
