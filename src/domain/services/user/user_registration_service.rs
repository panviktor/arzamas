use crate::domain::entities::shared::value_objects::OtpToken;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::Email;
use crate::domain::entities::user::user_registration::{
    UserRegistrationError, UserRegistrationResponse,
};
use crate::domain::entities::user::UserRegistration;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::ports::repositories::user::user_registration_dto::CreateUserDTO;
use crate::domain::ports::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::ValidationServiceError;
use chrono::{Duration, Utc};
use std::sync::Arc;

pub struct UserRegistrationDomainService<R, U>
where
    R: UserRegistrationDomainRepository,
    U: UserSharedDomainRepository,
{
    user_registration_repository: Arc<R>,
    user_repository: Arc<U>,
}

impl<R, U> UserRegistrationDomainService<R, U>
where
    R: UserRegistrationDomainRepository,
    U: UserSharedDomainRepository,
{
    pub fn new(user_registration_repository: Arc<R>, user_repository: Arc<U>) -> Self {
        Self {
            user_registration_repository,
            user_repository,
        }
    }

    pub async fn create_user(
        &self,
        user: CreateUserDTO,
    ) -> Result<UserRegistrationResponse, DomainError> {
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
        let token = SharedDomainService::generate_token(64)?;
        let confirmation_token = OtpToken::new(&token);
        let confirmation_token_hash = SharedDomainService::hash_token(&token);

        let user_id = UserId::new(&user.user_id);
        let user = self.user_registration_repository.create_user(user).await?;
        let expiry = Utc::now() + Duration::days(1);

        self.user_registration_repository
            .store_main_primary_activation_token(user_id, confirmation_token_hash, expiry)
            .await?;

        Ok(UserRegistrationResponse {
            user,
            email_validation_token: confirmation_token,
        })
    }

    pub async fn validate_user_primary_email_with_token(
        &self,
        email: Email,
        token: OtpToken,
    ) -> Result<(), DomainError> {
        let user = self.user_repository.get_base_user_by_email(email).await?;

        if user.email_validated {
            return Ok(());
        }

        let user_id = UserId::new(&user.user_id);

        let confirmation = self
            .user_registration_repository
            .get_primary_email_activation(&user_id)
            .await?;

        if SharedDomainService::validate_hash(&token.value(), &confirmation.otp_hash) {
            let now = Utc::now();
            if confirmation.expiry > now {
                self.user_registration_repository
                    .complete_primary_email_verification(&user_id)
                    .await
            } else {
                Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "Token has expired. \
                    You need to log in to the app to generate a new confirmation token."
                        .to_string(),
                )))
            }
        } else {
            Err(DomainError::ValidationError(ValidationError::InvalidData(
                "Invalid validation code provided.".to_string(),
            )))
        }
    }
}
