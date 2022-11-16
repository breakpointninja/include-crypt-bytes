use argon2::Config;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce, Error as CipherError,
};
use rand::RngCore;
use crypto_common::InvalidLength;

#[derive(thiserror::Error, Debug)]
pub enum CryptError {
    #[error("Hashing Failed: {0}")]
    HashError(#[from] argon2::Error),
    #[error("Cipher Failed: {0}")]
    CipherError(#[from] CipherError),
    #[error("Invalid length: {0}")]
    InvalidLength(#[from] InvalidLength),
}

type Result<T> = core::result::Result<T, CryptError>;

pub fn encrypt_bytes(bytes: &[u8], password: &[u8]) -> Result<(Vec<u8>, [u8; 12], [u8; 32])> {
    // Generate random salt and nonce
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    // Hash password for key
    let config = Config::default();
    let key = argon2::hash_raw(password, &salt, &config)?;

    // Encrypt
    let nonce_array = Nonce::from_slice(&nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    let ciphertext = cipher.encrypt(nonce_array, bytes)?;

    Ok((ciphertext, nonce, salt))
}

pub fn decrypt_bytes(
    bytes: &[u8],
    password: &[u8],
    nonce: &[u8; 12],
    salt: &[u8; 32],
) -> Result<Vec<u8>> {
    // Hash password for key
    let config = Config::default();
    let key = argon2::hash_raw(password, salt, &config)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())?;
    let nonce_array = Nonce::from_slice(nonce);

    Ok(cipher.decrypt(nonce_array, bytes)?)
}


#[test]
fn test_encrypt_decrypt() {
    let mut message = [0u8; 256];
    let mut password = [0u8; 64];
    OsRng.fill_bytes(&mut message);
    OsRng.fill_bytes(&mut password);
    let (ciphertext, nonce, salt) = encrypt_bytes(&message, &password).unwrap();
    let decrypted = decrypt_bytes(&ciphertext, &password, &nonce, &salt).unwrap();

    assert_eq!(message, decrypted.as_ref())
}

#[test]
fn test_encrypt_decrypt_err() {
    let mut message = [0u8; 256];
    let mut password = [0u8; 64];
    let mut invalid_password = [0u8; 64];
    OsRng.fill_bytes(&mut message);
    OsRng.fill_bytes(&mut password);
    OsRng.fill_bytes(&mut invalid_password);
    let (ciphertext, nonce, salt) = encrypt_bytes(&message, &password).unwrap();
    let decrypted = decrypt_bytes(&ciphertext, &invalid_password, &nonce, &salt);

    assert!(decrypted.is_err());
    assert_eq!(format!("{}", decrypted.err().unwrap()), "Cipher Failed: aead::Error");
}

#[test]
fn test_encrypt_zero_length() {
    let message: Vec<u8> = vec![];
    let password: Vec<u8> = vec![];
    let (ciphertext, nonce, salt) = encrypt_bytes(message.as_ref(), password.as_ref()).unwrap();
    let decrypted: Vec<u8> = decrypt_bytes(&ciphertext, password.as_ref(), &nonce, &salt).unwrap();

    assert_eq!(message, decrypted)
}
