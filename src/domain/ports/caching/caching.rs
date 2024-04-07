use crate::domain::entities::caching::caching::CachingError;
use chrono::Duration;

#[async_trait::async_trait]
pub trait CachingPort {
    async fn store_user_token(
        &self,
        user_id: &str,
        token: &str,
        expiry: Duration,
    ) -> Result<(), CachingError>;
    async fn get_user_token(&self, user_id: &str) -> Result<String, CachingError>;
}
