use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::error::{DomainError, ExternalServiceError, PersistenceError, ValidationError};
use crate::domain::services::user::user_validation_service::ValidationServiceError;
use crate::domain::services::user::{
    CredentialServiceError, UserCredentialService, UserValidationService,
};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct UserRegistration {
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub pass_hash: String,
    pub created_at: DateTime<Utc>,
}

pub struct UserRegistrationResponse {
    pub user: UserRegistration,
    pub email_validation_token: EmailToken,
}

pub enum UserRegistrationError {
    InvalidUsername(ValidationServiceError),
    InvalidPassword(ValidationServiceError),
    InvalidEmail(ValidationServiceError),
    CredentialError(CredentialServiceError),
}

impl UserRegistration {
    pub fn new(
        user_id: String,
        email: Email,
        username: Username,
        pass_hash: String,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            email,
            username,
            pass_hash,
            created_at,
        }
    }

    pub fn create(
        email: Email,
        username: Username,
        password: String,
    ) -> Result<Self, UserRegistrationError> {
        UserValidationService::validate_email(&email)
            .map_err(UserRegistrationError::InvalidEmail)?;
        UserValidationService::validate_username(&username)
            .map_err(UserRegistrationError::InvalidUsername)?;
        UserValidationService::validate_passwd(&password)
            .map_err(UserRegistrationError::InvalidPassword)?;

        let pass_hash = UserCredentialService::generate_password_hash(&password)
            .map_err(UserRegistrationError::CredentialError)?;
        let user_id = UserCredentialService::generate_user_id()
            .map_err(UserRegistrationError::CredentialError)?;
        let created_at = Utc::now();

        Ok(Self::new(user_id, email, username, pass_hash, created_at))
    }
}
impl From<UserRegistrationError> for DomainError {
    fn from(error: UserRegistrationError) -> Self {
        match error {
            UserRegistrationError::InvalidEmail(ve)
            | UserRegistrationError::InvalidUsername(ve)
            | UserRegistrationError::InvalidPassword(ve) => {
                DomainError::ValidationError(ValidationError::InvalidData(ve.to_string()))
            }
            UserRegistrationError::CredentialError(ce) => {
                match ce {
                    CredentialServiceError::HashingError(msg) => {
                        // Hashing might be considered an external service operation
                        DomainError::ExternalServiceError(ExternalServiceError::Custom(msg))
                    }
                    CredentialServiceError::UserIdGenerationError(msg) => {
                        // ID Generation might be considered a custom persistence operation
                        DomainError::PersistenceError(PersistenceError::Custom(msg))
                    }
                    CredentialServiceError::VerificationError(msg) => {
                        DomainError::ValidationError(ValidationError::InvalidData(msg))
                    }
                }
            }
        }
    }
}
