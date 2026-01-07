#ifndef PASSLIB_FFI_H
#define PASSLIB_FFI_H

#include <stdint.h>
#include <stddef.h>

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

// Memory management
void vault_free(CVault *vault);
void string_free(char *s);
void entry_free(CPasswordEntry *entry);
void entry_list_free(CPasswordEntryList *list);

#ifdef __cplusplus
}
#endif

#endif // PASSLIB_FFI_H
