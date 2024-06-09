use crate::domain::error::DomainError;

#[async_trait::async_trait]
pub trait CachingPort {
    async fn store_user_token(
        &self,
        user_id: &str,
        session_id: &str,
        token: &str,
        expiration_secs: u64,
    ) -> Result<(), DomainError>;
    async fn get_user_sessions_tokens(&self, user_id: &str) -> Result<Vec<String>, DomainError>;

    async fn invalidate_sessions(&self, user_id: &str) -> Result<(), DomainError>;
}
