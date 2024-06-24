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
        // Compute a Sha512 hash of the concatenated string
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_too_short() {
        let result = SharedDomainService::generate_token(5);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_token_valid_length() {
        let length = 10;
        let result = SharedDomainService::generate_token(length);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert_eq!(token.len(), length);
        // Ensure the token contains only alphanumeric characters
        assert!(token.chars().all(char::is_alphanumeric));
    }

    #[test]
    fn test_generate_token_longer_valid_length() {
        let length = 30;
        let result = SharedDomainService::generate_token(length);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert_eq!(token.len(), length);
        // Ensure the token contains only alphanumeric characters
        assert!(token.chars().all(char::is_alphanumeric));
    }

    #[test]
    fn test_hash_token() {
        let token = "test_token";
        let expected_hash = "cc0af97287543b65da2c7e1476426021826cab166f1e063ed012b855ff819656";

        let hash = SharedDomainService::hash_token(token);
        assert_eq!(hash, expected_hash);

        // Hashing the same token should always produce the same result
        let hash_again = SharedDomainService::hash_token(token);
        assert_eq!(hash, hash_again);
    }

    #[test]
    fn test_validate_hash() {
        let token = "test_token";
        let hash = SharedDomainService::hash_token(token);

        // The token should validate against its own hash
        let is_valid = SharedDomainService::validate_hash(token, &hash);
        assert!(is_valid);

        // A different token should not validate against the hash
        let is_invalid = SharedDomainService::validate_hash("different_token", &hash);
        assert!(!is_invalid);
    }
}
