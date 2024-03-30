use crate::infrastructure::web::middleware::rate_limiter;
/// Module that contains all the functions related to authentication.
use hex::encode;
use sha2::{Digest, Sha256};

use crate::core::error::ServerError;
use crate::err_server;

pub mod credentials;

pub mod models;
pub mod service;
pub mod session;
pub mod totp;
pub(crate) mod utils;

/// Generate a generic 32 byte token, and convert it to a hex string.
pub fn generate_email_verification_code() -> Result<String, ServerError> {
    let mut token = [0u8; 8];
    getrandom::getrandom(&mut token).map_err(|e| err_server!("Error generating token: {}", e))?;
    Ok(encode(token.to_vec()))
}

/// Hash a token with SHA256.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    encode(hasher.finalize())
}
