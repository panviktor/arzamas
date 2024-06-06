use crate::core::config::get_config;
use async_std::stream::StreamExt;

use crate::domain::error::DomainError;
use crate::domain::ports::caching::caching::CachingPort;
use crate::infrastructure::cache::error::CachingError;
use async_trait::async_trait;
use deadpool_redis::{CreatePoolError, Pool, Runtime};
use redis::{AsyncCommands, AsyncIter};
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
    async fn store_user_token(
        &self,
        user_id: &str,
        session_id: &str,
        token: &str,
        expiration_secs: u64,
    ) -> Result<(), DomainError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let key = format!("{}:{}", user_id, session_id);

        conn.set_ex(&key, token, expiration_secs)
            .await
            .map_err(|e| CachingError::SerializationError(e.to_string()))?;

        Ok(())
    }

    async fn get_user_sessions_tokens(&self, user_id: &str) -> Result<Vec<String>, DomainError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let keys_pattern = format!("{}:*", user_id);
        let mut iter: AsyncIter<String> = conn
            .scan_match(&keys_pattern)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let mut keys = Vec::new();
        while let Some(key) = iter.next().await {
            keys.push(key);
        }

        drop(iter);

        let mut pipe = redis::pipe();
        for key in &keys {
            pipe.get(key);
        }

        let tokens: Vec<Option<String>> = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let tokens: Vec<String> = tokens.into_iter().filter_map(|x| x).collect();

        Ok(tokens)
    }
}
