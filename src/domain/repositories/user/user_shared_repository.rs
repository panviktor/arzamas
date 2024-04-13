use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::EmailToken;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;

#[async_trait]
pub trait UserDomainRepository {
    async fn exists_with_email(&self, email: &Email) -> Result<bool, DomainError>;
    async fn exists_with_username(&self, username: &Username) -> Result<bool, DomainError>;
    async fn save_email_validation_token(
        &self,
        user: FindUserByIdDTO,
        token: &EmailToken,
    ) -> Result<(), DomainError>;
    async fn verify_email_validation_token(
        &self,
        user: FindUserByIdDTO,
        token: EmailToken,
    ) -> Result<bool, DomainError>;
}
