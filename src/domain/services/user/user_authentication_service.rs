use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::VerificationInfo;
use crate::domain::entities::user::user_registration::UserRegistrationError;
use crate::domain::entities::user::value_objects::UserIdentifier;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::repositories::user::user_shared_repository::UserDomainRepository;
use crate::domain::services::user::user_validation_service::EMAIL_REGEX;
use crate::domain::services::user::{UserValidationService, ValidationServiceError};
use std::sync::Arc;

pub struct UserAuthenticationDomainService<R, U>
where
    R: UserAuthenticationDomainRepository,
    U: UserDomainRepository,
{
    user_authentication_repository: R,
    user_repository: Arc<U>,
}

impl<R, U> UserAuthenticationDomainService<R, U>
where
    R: UserAuthenticationDomainRepository,
    U: UserDomainRepository,
{
    pub fn new(user_authentication_repository: R, user_repository: Arc<U>) -> Self {
        Self {
            user_authentication_repository,
            user_repository,
        }
    }
    pub async fn initiate_login(
        &self,
        identifier: UserIdentifier,
        password: String,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let identifier = identifier.into_inner();
        let is_email = EMAIL_REGEX.is_match(&identifier);
        if is_email {
            UserValidationService::validate_email(&Email::new(&identifier))?
        } else {
            UserValidationService::validate_username(&Username::new(&identifier))?
        };

        UserValidationService::validate_password(&password)?;
    }

    pub async fn continue_login(
        &self,
        user_id: String,
        verification_info: VerificationInfo,
    ) -> Result<AuthenticationOutcome, DomainError> {
        // 1. Retrieve the user's ongoing authentication flow state (possibly from a cache).
        // 2. Verify any provided 2FA codes or other verification details.
        // 3. Update the authentication flow state as necessary.
        // Return either a success token or prompt for further action as needed.
        todo!()
    }
}
