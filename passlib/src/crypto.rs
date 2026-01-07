use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2, ParamsBuilder, PasswordHasher,
};
use zeroize::Zeroize;

use crate::error::{PassError, Result};

/// Salt size for key derivation (32 bytes)
pub const SALT_SIZE: usize = 32;
/// Nonce size for AES-GCM (12 bytes)
pub const NONCE_SIZE: usize = 12;
/// Authentication tag size (16 bytes)
pub const TAG_SIZE: usize = 16;

/// Derives a 256-bit encryption key from a master password using Argon2id
///
/// Parameters are tuned for security while being reasonable for interactive use:
/// - Memory cost: 64 MB
/// - Time cost: 3 iterations
/// - Parallelism: 4 lanes
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    // Use Argon2id (hybrid mode, resistant to both side-channel and GPU attacks)
    let _argon2 = Argon2::default();
    
    // Build custom parameters for interactive use
    let params = ParamsBuilder::new()
        .m_cost(65536) // 64 MB
        .t_cost(3)     // 3 iterations
        .p_cost(4)     // 4 parallel lanes
        .build()
        .map_err(|e| PassError::CryptoError(format!("Failed to build Argon2 params: {}", e)))?;
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    // Hash the password
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| PassError::CryptoError(format!("Invalid salt: {}", e)))?;
    
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| PassError::CryptoError(format!("Key derivation failed: {}", e)))?;

    // Extract the 32-byte key from the hash
    let hash_bytes = hash.hash.ok_or_else(|| {
        PassError::CryptoError("Hash output is empty".to_string())
    })?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
    
    Ok(key)
}

/// Generate a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a cryptographically secure random nonce
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt data using AES-256-GCM
///
/// Returns the encrypted ciphertext (including the authentication tag)
pub fn encrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_obj = Nonce::from_slice(nonce);
    
    cipher
        .encrypt(nonce_obj, data)
        .map_err(|e| PassError::CryptoError(format!("Encryption failed: {}", e)))
}

/// Decrypt data using AES-256-GCM
///
/// Verifies the authentication tag and returns the plaintext if valid
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_obj = Nonce::from_slice(nonce);
    
    cipher
        .decrypt(nonce_obj, ciphertext)
        .map_err(|_| PassError::InvalidPassword) // Most common cause is wrong password
}

/// Securely zeroize a key from memory
pub fn zeroize_key(key: &mut [u8; 32]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_consistency() {
        let password = "test_password_123";
        let salt = generate_salt();
        
        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();
        
        assert_eq!(key1, key2, "Same password and salt should produce same key");
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let password = "test_password_123";
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        
        let key1 = derive_key(password, &salt1).unwrap();
        let key2 = derive_key(password, &salt2).unwrap();
        
        assert_ne!(key1, key2, "Different salts should produce different keys");
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let data = b"Secret password data that needs protection";
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let nonce = generate_nonce();
        
        let encrypted = encrypt(data, &key, &nonce).unwrap();
        assert_ne!(encrypted.as_slice(), data, "Encrypted data should differ from plaintext");
        
        let decrypted = decrypt(&encrypted, &key, &nonce).unwrap();
        assert_eq!(decrypted, data, "Decrypted data should match original");
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let data = b"Secret data";
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        OsRng.fill_bytes(&mut key1);
        OsRng.fill_bytes(&mut key2);
        let nonce = generate_nonce();
        
        let encrypted = encrypt(data, &key1, &nonce).unwrap();
        let result = decrypt(&encrypted, &key2, &nonce);
        
        assert!(result.is_err(), "Decryption with wrong key should fail");
        assert!(matches!(result.unwrap_err(), PassError::InvalidPassword));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let data = b"Secret data";
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let nonce = generate_nonce();
        
        let mut encrypted = encrypt(data, &key, &nonce).unwrap();
        // Tamper with the ciphertext
        encrypted[5] ^= 0xFF;
        
        let result = decrypt(&encrypted, &key, &nonce);
        assert!(result.is_err(), "Tampered ciphertext should fail authentication");
    }
}
