use crate::store::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

pub fn token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn id() -> String {
    token().replace('-', "a").replace('_', "b")
}
pub fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}
pub fn password_hash(password: &str) -> Result<String> {
    if !(14..=128).contains(&password.len()) {
        return Err(Error::Invalid("contraseña de 14 a 128 bytes"));
    }
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|v| v.to_string())
        .map_err(|_| Error::Invalid("contraseña inválida"))
}
pub fn password_matches(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}
pub fn encrypt(key: &[u8; 32], user_id: &str, data: &[u8]) -> Result<String> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = Aes256Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: data,
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| Error::Invalid("cifrado"))?;
    Ok(URL_SAFE_NO_PAD.encode([nonce.as_slice(), encrypted.as_slice()].concat()))
}
pub fn decrypt(key: &[u8; 32], user_id: &str, value: &str) -> Result<Vec<u8>> {
    let data = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::Unauthorized)?;
    if data.len() < 28 {
        return Err(Error::Unauthorized);
    }
    Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(&data[..12]),
            Payload {
                msg: &data[12..],
                aad: user_id.as_bytes(),
            },
        )
        .map_err(|_| Error::Unauthorized)
}
pub fn new_totp_secret() -> Vec<u8> {
    let mut v = vec![0u8; 20];
    OsRng.fill_bytes(&mut v);
    v
}
pub fn totp(secret: &[u8]) -> Result<TOTP> {
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.to_vec())
        .map_err(|_| Error::Invalid("MFA inválido"))
}
pub fn secret_base32(secret: &[u8]) -> String {
    Secret::Raw(secret.to_vec()).to_encoded().to_string()
}
pub fn totp_counter(secret: &[u8], code: &str, now: i64, last: i64) -> Result<i64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) || now < 30 {
        return Err(Error::Unauthorized);
    }
    let totp = totp(secret)?;
    for counter in [now / 30, now / 30 - 1, now / 30 + 1] {
        if counter > last
            && totp.check(code, counter as u64 * 30)
            && totp.generate(counter as u64 * 30) == code
        {
            return Ok(counter);
        }
    }
    Err(Error::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_and_encryption() {
        let hash = password_hash("UnaClaveLargaSoloTest").unwrap();
        assert!(password_matches("UnaClaveLargaSoloTest", &hash));
        assert!(!password_matches("incorrecta", &hash));
        let encrypted = encrypt(&[3; 32], "user1", b"secret").unwrap();
        assert_eq!(decrypt(&[3; 32], "user1", &encrypted).unwrap(), b"secret");
        assert!(decrypt(&[3; 32], "user2", &encrypted).is_err());
    }
    #[test]
    fn no_totp_bypass_or_reuse() {
        let secret = [7; 20];
        let code = totp(&secret).unwrap().generate(120);
        assert_eq!(totp_counter(&secret, &code, 120, -1).unwrap(), 4);
        assert!(totp_counter(&secret, &code, 120, 4).is_err());
        assert!(totp_counter(&secret, "000000", 120, -1).is_err());
    }
}
