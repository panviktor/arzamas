use crate::domain::entities::shared::Email;
use crate::domain::error::DomainError;
use async_trait::async_trait;

#[async_trait]
pub trait UserDomainRepository {
    async fn exists_with_email(&self, email: &Email) -> Result<bool, DomainError>;
    async fn exists_with_username(&self, username: &str) -> Result<bool, DomainError>;
}
