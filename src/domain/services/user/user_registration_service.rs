use crate::domain::entities::user::UserRegistration;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_parameters::FindUser;
use crate::domain::repositories::user::user_registration_repository::UserRegistrationDomainRepository;

pub struct UserRegistrationDomainService<R: UserRegistrationDomainRepository> {
    user_registration_repository: R,
}

impl<R> UserRegistrationDomainService<R>
where
    R: UserRegistrationDomainRepository,
{
    pub fn new(user_registration_repository: R) -> Self {
        Self {
            user_registration_repository,
        }
    }

    pub async fn create_user(
        &self,
        user: UserRegistration,
    ) -> Result<UserRegistration, DomainError> {
        self.user_registration_repository.create_user(user).await
    }

    pub async fn delete_user(&self, user: FindUser) -> Result<(), DomainError> {
        self.user_registration_repository.delete_user(user).await
    }
}
