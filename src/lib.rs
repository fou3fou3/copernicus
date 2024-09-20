use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());

    let hash = hasher.finalize();
    general_purpose::STANDARD.encode(hash)
}
