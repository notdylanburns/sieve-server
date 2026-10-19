use std::sync::LazyLock;

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};

pub use argon2::password_hash::Error;

pub fn hash(password: &str) -> Result<Box<str>, Error> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())?
        .to_string()
        .into())
}

pub fn verify(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

/// Costs the same as a real verification, so unknown usernames can't be detected by timing.
pub fn verify_dummy(password: &str) {
    static DUMMY: LazyLock<Box<str>> =
        LazyLock::new(|| hash("dummy").expect("hashing a constant cannot fail"));
    verify(password, &DUMMY);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_only_the_hashed_password() {
        let hashed = hash("correct horse").unwrap();
        assert!(hashed.starts_with("$argon2id$"));
        assert!(verify("correct horse", &hashed));
        assert!(!verify("battery staple", &hashed));
        assert!(!verify("correct horse", "not a hash"));
    }
}
