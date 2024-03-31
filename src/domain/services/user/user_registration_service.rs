use crate::domain::entities::user::user_registration::UserRegistrationError;
use crate::domain::entities::user::UserRegistration;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_parameters::FindUserByIdDTO;
use crate::domain::repositories::user::user_registration_parameters::CreateUserDTO;
use crate::domain::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::repositories::user::user_repository::UserDomainRepository;
use crate::domain::services::user::ValidationServiceError;
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

    pub async fn create_user(&self, user: CreateUserDTO) -> Result<UserRegistration, DomainError> {
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
        self.user_registration_repository.create_user(user).await
    }

    pub async fn delete_user(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        self.user_registration_repository.delete_user(user).await
    }
}
