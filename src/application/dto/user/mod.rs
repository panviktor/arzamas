use crate::application::error::error::ApplicationError;
use crate::domain::entities::user::user_registration::UserRegistrationError;
use crate::domain::services::user::CredentialServiceError;

pub mod user_registration_request_dto;
pub mod user_registration_response_dto;

impl From<UserRegistrationError> for ApplicationError {
    fn from(error: UserRegistrationError) -> Self {
        match error {
            UserRegistrationError::InvalidUsername(ve)
            | UserRegistrationError::InvalidPassword(ve)
            | UserRegistrationError::InvalidEmail(ve) => {
                ApplicationError::ValidationError(ve.to_string())
            }
            UserRegistrationError::CredentialError(ce) => match ce {
                CredentialServiceError::HashingError(msg)
                | CredentialServiceError::UserIdGenerationError(msg) => {
                    ApplicationError::DatabaseError(msg)
                }
            },
        }
    }
}
