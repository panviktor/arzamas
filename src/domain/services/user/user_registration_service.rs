use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::user::user_registration::{
    UserRegistrationError, UserRegistrationOutcome,
};
use crate::domain::entities::user::UserRegistration;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::repositories::user::user_registration_parameters::CreateUserDTO;
use crate::domain::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::FindUserByIdDTO;
use crate::domain::repositories::user::user_shared_repository::UserDomainRepository;
use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::ValidationServiceError;
use chrono::{Duration, Utc};
use std::sync::Arc;

pub struct UserRegistrationDomainService<R, U>
where
    R: UserRegistrationDomainRepository,
    U: UserDomainRepository,
{
    user_registration_repository: R,
    user_repository: Arc<U>,
}

impl<R, U> UserRegistrationDomainService<R, U>
where
    R: UserRegistrationDomainRepository,
    U: UserDomainRepository,
{
    pub fn new(user_registration_repository: R, user_repository: Arc<U>) -> Self {
        Self {
            user_registration_repository,
            user_repository,
        }
    }

    pub async fn create_user(
        &self,
        user: CreateUserDTO,
    ) -> Result<UserRegistrationOutcome, DomainError> {
        if self.user_repository.exists_with_email(&user.email).await? {
            return Err(UserRegistrationError::InvalidEmail(
                ValidationServiceError::InvalidFormat("Email already exists".to_string()),
            )
            .into());
        }

        if self
            .user_repository
            .exists_with_username(&user.username)
            .await?
        {
            return Err(UserRegistrationError::InvalidEmail(
                ValidationServiceError::InvalidFormat("Username already exists".to_string()),
            )
            .into());
        }

        let user = UserRegistration::create(user.email, user.username, user.password)?;
        let token = SharedDomainService::generate_token(8)?;
        let confirmation_token = EmailToken::new(&token);
        let confirmation_token_hash = SharedDomainService::hash_token(&token);

        let user_id = FindUserByIdDTO::new(&user.user_id);

        let user = self.user_registration_repository.create_user(user).await?;
        let expiry = Utc::now() + Duration::days(1);

        self.user_repository
            .store_email_confirmation_token(user_id, confirmation_token_hash, expiry)
            .await?;

        Ok(UserRegistrationOutcome {
            user,
            email_validation_token: confirmation_token,
        })
    }

    pub async fn delete_user(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        self.user_registration_repository.delete_user(user).await
    }

    pub async fn validate_email_user(
        &self,
        user: FindUserByIdDTO,
        token: String,
    ) -> Result<(), DomainError> {
        let confirmation = self
            .user_repository
            .retrieve_email_confirmation_token(&user)
            .await?;

        if SharedDomainService::validate_hash(&token, &confirmation.otp_hash) {
            let now = Utc::now();
            if confirmation.expiry > now {
                self.user_repository.complete_email_verification(user).await
            } else {
                Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "Token has expired.".to_string(),
                )))
            }
        } else {
            Err(DomainError::ValidationError(ValidationError::InvalidData(
                "Invalid validation code provided.".to_string(),
            )))
        }
    }
}