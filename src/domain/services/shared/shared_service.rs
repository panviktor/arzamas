use crate::domain::error::{DomainError, ExternalServiceError};
use chrono::Utc;
use hex::encode;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use std::iter;
use uuid::Uuid;

pub struct SharedDomainService;

#[derive(Debug, Clone)]
pub enum SharedDomainError {
    TokenGenerationError(String),
    TokenTooShort(String),
}

impl SharedDomainError {
    fn from_getrandom_error(e: getrandom::Error) -> Self {
        SharedDomainError::TokenGenerationError(format!("Error generating token: {}", e))
    }
}
impl SharedDomainService {
    pub fn generate_token(length: usize) -> Result<String, SharedDomainError> {
        if length < 10 {
            return Err(SharedDomainError::TokenTooShort(
                "Token length should be at least 10 characters.".to_string(),
            ));
        }

        let token: String = iter::repeat_with(|| rand::thread_rng().sample(Alphanumeric))
            .take(length)
            .map(char::from)
            .collect();

        Ok(token)
    }

    pub fn generate_unique_id() -> String {
        // Generate a new UUID
        let uuid = Uuid::new_v4().to_string();
        // Get the current date and time in UTC
        let utc_time = Utc::now();
        // Concatenate the UUID with the date and time in ISO-8601 format
        let id_str = format!("{}-{}", uuid, utc_time.to_rfc3339());
        // Compute a SHA-256 hash of the concatenated string
        let mut hasher = Sha512::new();
        hasher.update(id_str.as_bytes());
        encode(hasher.finalize())
    }

    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        encode(hasher.finalize())
    }

    pub fn validate_hash(token: &str, hash: &str) -> bool {
        Self::hash_token(token) == hash
    }
}

impl From<SharedDomainError> for DomainError {
    fn from(error: SharedDomainError) -> Self {
        match error {
            SharedDomainError::TokenTooShort(msg)
            | SharedDomainError::TokenGenerationError(msg) => {
                DomainError::ExternalServiceError(ExternalServiceError::Custom(msg))
            }
        }
    }
}
