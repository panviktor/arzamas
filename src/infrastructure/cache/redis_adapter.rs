use crate::core::config::get_config;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::error::DomainError;
use crate::domain::ports::caching::caching::CachingPort;
use crate::infrastructure::cache::error::CachingError;
use async_trait::async_trait;
use deadpool_redis::redis::AsyncCommands;
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
    /// Stores a user's session token in Redis with an expiration time.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier for the user.
    /// * `session_id` - The unique identifier for the session.
    /// * `token` - The JWT token string.
    /// * `expiration_timestamp` - The absolute expiration time as a UNIX timestamp.
    async fn store_user_token(
        &self,
        user_id: &str,
        session_id: &str,
        token: &str,
        expiration_timestamp: u64,
    ) -> Result<(), DomainError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let session_key = format!("session:{}", session_id);
        let user_sessions_key = format!("user_sessions:{}", user_id);

        // Calculate TTL as the difference between expiration_timestamp and current time
        let current_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CachingError::SerializationError(e.to_string()))?
            .as_secs();

        if expiration_timestamp <= current_timestamp {
            return Err(CachingError::SerializationError(
                "Expiration time must be in the future".to_string(),
            )
            .into());
        }

        let ttl = expiration_timestamp - current_timestamp;

        // Store the token and user_id in a hash
        // HSET doesn't set expiration, so we use EXPIRE after.
        let _: () = conn
            .hset_multiple(&session_key, &[("token", token), ("user_id", user_id)])
            .await
            .map_err(|e| CachingError::SerializationError(e.to_string()))?;

        // Set expiration on the session key
        let _: () = conn
            .expire(&session_key, ttl as i64)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        // Add session_id to the user's set of sessions
        let _: () = conn
            .sadd(&user_sessions_key, session_id)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        Ok(())
    }

    /// Retrieves the token and user_id for a given session_id.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The unique identifier for the session.
    async fn get_user_session_token(
        &self,
        session_id: &str,
    ) -> Result<(String, String), DomainError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let session_key = format!("session:{}", session_id);

        let (token, user_id): (Option<String>, Option<String>) = conn
            .hget(&session_key, &["token", "user_id"])
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        match (token, user_id) {
            (Some(t), Some(u)) => Ok((t, u)),
            _ => Err(CachingError::NotFound(
                "Token or user_id not found for this session".to_string(),
            )
            .into()),
        }
    }
    /// Retrieves all active tokens for a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier for the user.
    async fn get_user_sessions_tokens(&self, user_id: &str) -> Result<Vec<String>, DomainError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let user_sessions_key = format!("user_sessions:{}", user_id);

        // Get all session_ids for the user
        let session_ids: Vec<String> = conn
            .smembers(&user_sessions_key)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        if session_ids.is_empty() {
            return Err(CachingError::NotFound("No sessions found for user".to_string()).into());
        }

        let mut tokens = Vec::with_capacity(session_ids.len());

        // For each session, retrieve the token field
        for sid in session_ids {
            let session_key = format!("session:{}", sid);
            let token: Option<String> = conn
                .hget(&session_key, "token")
                .await
                .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

            if let Some(t) = token {
                tokens.push(t);
            }
        }

        if tokens.is_empty() {
            return Err(
                CachingError::NotFound("No valid tokens found for user".to_string()).into(),
            );
        }

        Ok(tokens)
    }

    /// Invalidates all sessions for a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier for the user.
    async fn invalidate_sessions(&self, user_id: &str) -> Result<(), DomainError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let user_sessions_key = format!("user_sessions:{}", user_id);
        let session_ids: Vec<String> = conn
            .smembers(&user_sessions_key)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        if session_ids.is_empty() {
            return Err(CachingError::NotFound("No sessions found for user".to_string()).into());
        }

        // Delete each session hash
        let session_keys: Vec<String> = session_ids
            .iter()
            .map(|session_id| format!("session:{}", session_id))
            .collect();

        let _: () = conn
            .del(&session_keys)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        // Remove the user_sessions set
        let _: () = conn
            .del(&user_sessions_key)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        Ok(())
    }

    /// Invalidates a single session for a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The unique identifier for the user.
    /// * `session_id` - The unique identifier for the session.
    async fn invalidate_session(&self, user_id: &str, session_id: &str) -> Result<(), DomainError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        let session_key = format!("session:{}", session_id);
        let user_sessions_key = format!("user_sessions:{}", user_id);

        let result: u32 = conn
            .del(&session_key)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        if result == 0 {
            return Err(CachingError::NotFound("Session not found".to_string()).into());
        }

        let _: () = conn
            .srem(&user_sessions_key, session_id)
            .await
            .map_err(|e| CachingError::ConnectionFailure(e.to_string()))?;

        Ok(())
    }
}
