use crate::core::config::get_config;

use actix_web::http::StatusCode;
use deadpool_redis::{CreatePoolError, Pool, PoolError, Runtime};
use redis::RedisError;
use secrecy::ExposeSecret;
use crate::application::error::response_error::AppResponseError;
use crate::core::error::{ErrorCode, ServerError};

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

impl From<RedisError> for AppResponseError {
    fn from(err: RedisError) -> Self {
        AppResponseError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: Option::from("redis".to_string()),
            message: err.to_string(),
            show_message: true,
        }
    }
}

impl From<RedisError> for ServerError {
    fn from(value: RedisError) -> Self {
        ServerError {
            code: ErrorCode::ServerError,
            message: value.to_string(),
            show_message: true,
        }
    }
}

impl From<PoolError> for ServerError {
    fn from(error: PoolError) -> Self {
        ServerError {
            code: ErrorCode::ServerError,
            message: error.to_string(),
            show_message: true,
        }
    }
}
