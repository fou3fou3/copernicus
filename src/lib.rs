use std::error::Error;

use askama::Template;
use base64::{engine::general_purpose, Engine as _};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::LineEnding,
    RsaPrivateKey, RsaPublicKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub fn hash_password(password: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());

    let hash = hasher.finalize();
    general_purpose::STANDARD.encode(hash)
}

pub fn generate_rsa_keys() -> Result<(String, String), Box<dyn Error>> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    let public_key_pem = public_key.to_pkcs1_pem(LineEnding::LF)?;

    Ok((private_key_pem.to_string(), public_key_pem))
}

#[derive(Template)]
#[template(path = "get_user.html")]
pub struct GetUserTemplate<'a> {
    pub user_name: &'a str,
}

// AuthUser is the user type that we use to login/sign in (auth)
#[derive(Deserialize)]
pub struct AuthUser {
    pub user_name: String,
    pub password: String,
}

pub struct InsertUser {
    pub user_name: String,
    pub password_hash: String,
    pub public_key: String,
}
