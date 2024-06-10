use crate::domain::error::{DomainError, ExternalServiceError};
use crate::domain::services::shared::SharedDomainService;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::distributions::Alphanumeric;
use rand::Rng;
use unicode_normalization::UnicodeNormalization;
#[derive(Debug, Clone)]
pub enum CredentialServiceError {
    HashingError(String),
    UserIdGenerationError(String),
    VerificationError(String),
}

pub struct UserCredentialService;

impl UserCredentialService {
    /// Generate a password hash from the supplied password, using a random salt
    pub fn generate_password_hash(password: &str) -> Result<String, CredentialServiceError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let normalize_password = Self::normalize_string(password);
        let password_hash = argon2.hash_password(normalize_password.as_bytes(), &salt);

        match password_hash {
            Ok(hash) => Ok(hash.to_string()),
            Err(e) => Err(CredentialServiceError::HashingError(e.to_string())),
        }
    }

    pub fn generate_user_id() -> Result<String, CredentialServiceError> {
        let random_suffix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();

        let mut token = SharedDomainService::generate_token(32).map_err(|e| {
            CredentialServiceError::UserIdGenerationError(format!(
                "Error generating token: {:?}",
                e
            ))
        })?;
        token.push_str(&random_suffix);
        Ok(token)
    }

    pub fn credential_validator(
        password: &str,
        password_hash: &str,
    ) -> Result<bool, CredentialServiceError> {
        // Normalize the input password
        let normalize_password = Self::normalize_string(password);
        // Parse the stored password hash
        let parsed_hash = PasswordHash::new(password_hash).map_err(|_| {
            CredentialServiceError::VerificationError("Invalid hash format.".to_string())
        })?;

        Argon2::default()
            .verify_password(normalize_password.as_bytes(), &parsed_hash)
            .map(|()| true)
            .map_err(|_| {
                CredentialServiceError::VerificationError(
                    "Password verification failed.".to_string(),
                )
            })
    }

    fn normalize_string(s: &str) -> String {
        s.nfkc().collect::<String>()
    }
}

impl From<CredentialServiceError> for DomainError {
    fn from(error: CredentialServiceError) -> Self {
        match error {
            CredentialServiceError::HashingError(msg) => DomainError::ExternalServiceError(
                ExternalServiceError::Custom(format!("Hashing error: {}", msg)),
            ),
            CredentialServiceError::UserIdGenerationError(msg) => {
                DomainError::ExternalServiceError(ExternalServiceError::Custom(format!(
                    "User ID generation error: {}",
                    msg
                )))
            }
            CredentialServiceError::VerificationError(msg) => DomainError::ExternalServiceError(
                ExternalServiceError::Custom(format!("Verification error: {}", msg)),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generate_user_id() {
        let result = UserCredentialService::generate_user_id();
        assert!(result.is_ok());

        let user_id = result.unwrap();
        assert_eq!(user_id.len(), 37);
        assert!(user_id.chars().all(char::is_alphanumeric));
    }
}
