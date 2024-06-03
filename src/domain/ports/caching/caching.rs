use crate::domain::error::DomainError;

#[async_trait::async_trait]
pub trait CachingPort {
    async fn store_user_token(&self, user_id: &str, token: &str) -> Result<(), DomainError>;
    async fn get_user_token(&self, user_id: &str) -> Result<String, DomainError>;
}
