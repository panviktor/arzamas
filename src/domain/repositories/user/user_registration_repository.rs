use crate::domain::entities::user::UserRegistration;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;

#[async_trait]
pub trait UserRegistrationDomainRepository {
    /// Create the received user entity in the persistence system
    async fn create_user(&self, user: UserRegistration) -> Result<UserRegistration, DomainError>;

    /// Delete the received user entity in the persistence system
    async fn delete_user(&self, user: FindUserByIdDTO) -> Result<(), DomainError>;
}
