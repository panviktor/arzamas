use lazy_static::lazy_static;
use redis::{Client, RedisError};
use crate::models::{ErrorCode, ServerError, ServiceError};
use actix_web::http::StatusCode;
use crate::core::config::get_config;
use secrecy::ExposeSecret;

lazy_static! {
     pub static ref REDIS_CLIENT: Client = {
        let config = get_config().expect("Failed to read configuration.");

        let redis_host_name = config.redis_settings.host;
        let redis_port_address = config.redis_settings.port;
        let redis_password = config.redis_settings.password.expose_secret();

        let con_info = redis::ConnectionInfo {
            addr: redis::ConnectionAddr::Tcp(redis_host_name, redis_port_address),
            redis: redis::RedisConnectionInfo {
                db: 0,
                username: None,
                password: Some(redis_password.to_string()) }
        };

        Client::open(con_info)
            .expect("Invalid connection URL")
    };
}

impl From<RedisError> for ServiceError {
    fn from(err: RedisError) -> Self {
        ServiceError {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            path: "redis".to_string(),
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