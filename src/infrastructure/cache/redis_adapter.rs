use crate::core::config::get_config;

use crate::domain::error::DomainError;
use crate::domain::ports::caching::caching::CachingPort;
use async_trait::async_trait;
use deadpool_redis::{CreatePoolError, Pool, Runtime};
use secrecy::ExposeSecret;

pub fn create_redis_pool() -> Result<Pool, CreatePoolError> {
    let config = get_config().expect("Failed to read configuration.");
    let redis_url = format!(
        "redis://:{}@{}:{}/{}",
        config.redis_settings.password.expose_secret(),
        config.redis_settings.host,
        config.redis_settings.port,
        0 // Assuming database index is 0
    );
    let cfg = deadpool_redis::Config::from_url(&redis_url);
    let pool = cfg.create_pool(Some(Runtime::Tokio1))?;
    Ok(pool)
}

pub struct RedisAdapter {
    pool: Pool,
}

impl RedisAdapter {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CachingPort for RedisAdapter {
    async fn store_user_token(&self, user_id: &str, token: &str) -> Result<(), DomainError> {
        //
        todo!()
    }

    async fn get_user_token(&self, user_id: &str) -> Result<String, DomainError> {
        //
        todo!()
    }
}
