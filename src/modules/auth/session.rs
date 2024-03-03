use actix_http::header::HeaderValue;
use actix_web::dev::ServiceRequest;
use actix_web::{web, HttpRequest};
use chrono::{Duration, TimeZone, Utc};
use deadpool_redis::Pool;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::option::Option;
use uuid::Uuid;

use crate::core::config::APP_SETTINGS;
use crate::core::constants::core_constants;
use crate::core::constants::emojis::EMOJIS;

use crate::err_server;
use crate::models::ServerError;
use crate::application::error::service_error::ServiceError;
use crate::modules::auth::models::UserToken;

fn generate_random_name() -> String {
    use rand::seq::SliceRandom;
    let mut rng = &mut rand::thread_rng();

    EMOJIS
        .choose_multiple(&mut rng, 5)
        .cloned()
        .collect::<String>()
        .to_string()
}

pub fn generate_token(
    user: &str,
    login_session: &str,
    login_ip: &str,
    user_agent: &str,
    exp: i64,
) -> Result<String, ServerError> {
    let now = Utc::now()
        .timestamp_nanos_opt()
        .ok_or_else(|| err_server!("Failed to get nanosecond timestamp for issued at time"))?;

    let payload = UserToken {
        iat: now,
        exp,
        user_id: user.to_string(),
        session_id: login_session.to_string(),
        session_name: generate_random_name(),
        login_ip: login_ip.to_string(),
        user_agent: user_agent.to_string(),
    };

    let result = jsonwebtoken::encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
    )
        .map_err(|e| err_server!("Unable to generate session token.:{}", e))?;

    Ok(result)
}

// Create a session token for a specific user
pub async fn generate_session_token(
    user: &str,
    persistent: bool,
    login_ip: &str,
    user_agent: &str,
    redis_pool: &Pool,
) -> Result<String, ServerError> {
    let expiry = Utc::now()
        + if persistent {
        Duration::days(7)
    } else {
        Duration::days(1)
    };
    let login_session = Uuid::new_v4().to_string();

    let expiry_timestamp_nanos = expiry
        .timestamp_nanos_opt()
        .ok_or_else(|| err_server!("Failed to get nanosecond timestamp"))?;

    let token = generate_token(
        user,
        &login_session,
        login_ip,
        user_agent,
        expiry_timestamp_nanos,
    )
        .map_err(|e| err_server!("Unable to generate session token: {}", e))?;

    let mut conn = redis_pool
        .get()
        .await
        .map_err(|e| err_server!("{}", format!("Failed to get Redis connection: {}", e)))?;

    conn.hset(user, &login_session, &token)
        .await
        .map_err(|e| err_server!("{}", format!("Failed to set value in Redis: {}", e)))?;

    Ok(token)
}

pub fn decode_token(token: &str) -> jsonwebtoken::errors::Result<TokenData<UserToken>> {
    jsonwebtoken::decode::<UserToken>(
        &token,
        &DecodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
        &Validation::default(),
    )
}

/// Extract the session token from ServiceRequest
pub fn get_session_token_service_request(req: &ServiceRequest) -> Option<String> {
    if let Some(authed_header) = req.headers().get(core_constants::AUTHORIZATION) {
        extract_token(authed_header)
    } else {
        None
    }
}

/// Extract the session token from ServiceRequest
pub fn get_session_token_http_request(req: &HttpRequest) -> Option<String> {
    if let Some(authed_header) = req.headers().get(core_constants::AUTHORIZATION) {
        extract_token(authed_header)
    } else {
        None
    }
}

fn extract_token(authed_header: &HeaderValue) -> Option<String> {
    if let Ok(authed_header_str) = authed_header.to_str() {
        if authed_header_str.starts_with(core_constants::BEARER) {
            let token = authed_header_str[6..authed_header_str.len()].trim();
            return Some(token.to_string());
        }
    }
    None
}

/// Get username from session token
pub async fn validate_session(
    token_from_req: &str,
    redis_pool: &Pool,
) -> Result<Option<String>, ServerError> {
    if let Ok(decoded_data) = decode_token(token_from_req) {
        // Get a connection from the pool
        let mut conn = redis_pool
            .get()
            .await
            .map_err(|e| err_server!("{}", format!("Failed to get Redis connection: {}", e)))?;

        let user = decoded_data.claims.user_id.to_string();
        let session_id = decoded_data.claims.session_id.to_string();
        let token_from_redis: String = conn
            .hget(&user, &session_id)
            .await
            .map_err(|e| err_server!("{}", format!("Failed to get token from Redis: {}", e)))?;

        if token_from_redis == token_from_req {
            let now = Utc::now();
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime > now {
                return Ok(Some(user));
            } else {
                conn.hdel(&user, &session_id).await.map_err(|e| {
                    err_server!(
                        "{}",
                        format!("Failed to delete expired token from Redis: {}", e)
                    )
                })?;
            }
        }
    }
    Ok(None)
}

async fn valid_sessions(
    tokens: Vec<String>,
    redis_pool: &Pool,
) -> Result<Vec<UserToken>, ServerError> {
    let now = Utc::now();
    let mut valid_tokens: Vec<UserToken> = vec![];
    // Get a connection from the pool
    let mut conn = redis_pool
        .get()
        .await
        .map_err(|e| err_server!("{}", format!("Failed to get Redis connection: {}", e)))?;

    for token_str in tokens.iter() {
        if let Ok(decoded_data) = decode_token(token_str) {
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime > now {
                let token = decoded_data.claims;
                valid_tokens.push(token)
            } else {
                conn.hdel(
                    &decoded_data.claims.user_id,
                    &decoded_data.claims.session_id,
                )
                    .await
                    .map_err(|e| {
                        err_server!(
                        "{}",
                        format!("Failed to delete expired token from Redis: {}", e)
                    )
                    })?;
            }
        }
    }
    Ok(valid_tokens)
}

pub async fn try_active_sessions(
    req: &HttpRequest,
    user: &str,
) -> Result<Vec<UserToken>, ServiceError> {
    let redis_pool = req
        .app_data::<web::Data<Pool>>()
        .ok_or_else(|| ServiceError::general(&req, "Failed to extract Redis pool", true))?;

    let mut client = redis_pool.get().await.map_err(|e| {
        ServiceError::general(
            &req,
            format!("Failed to get Redis connection: {}", e),
            false,
        )
    })?;

    let tokens: HashMap<String, String> = client.hgetall(user.to_string()).await?;
    let token_values = tokens.values().cloned().collect();
    // Validate the tokens
    valid_sessions(token_values, &redis_pool)
        .await
        .map_err(|e| ServiceError::general(req, e.to_string(), false))
}

pub async fn try_current_active_session(req: &HttpRequest) -> Result<UserToken, ServiceError> {
    let redis_pool = req
        .app_data::<web::Data<Pool>>() // Make sure Pool is the type of your Redis connection pool
        .ok_or_else(|| ServiceError::general(&req, "Failed to extract Redis pool", true))?;

    if let Some(token) = get_session_token_http_request(req) {
        if let Ok(decoded_data) = decode_token(&token) {
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            let now = Utc::now();

            if datetime > now {
                // Get a Redis connection from the pool
                let mut con = redis_pool.get().await.map_err(|e| {
                    ServiceError::general(
                        req,
                        format!("Failed to get Redis connection: {}", e),
                        true,
                    )
                })?;

                let user = decoded_data.claims.user_id.to_string();
                let session_id = decoded_data.claims.session_id.to_string();

                let token_from_redis: String = con.hget(&user, &session_id).await.map_err(|e| {
                    ServiceError::general(
                        req,
                        format!("Failed to fetch token from Redis: {}", e),
                        false,
                    )
                })?;

                if token_from_redis == token {
                    return Ok(decoded_data.claims);
                }
            }
        }
    }
    Err(ServiceError::not_found(
        req,
        "Error get session token http request".to_string(),
        false,
    ))
}

pub async fn try_remove_all_sessions_token(
    req: &HttpRequest,
    user: &str,
) -> Result<bool, ServiceError> {
    let redis_pool = req
        .app_data::<web::Data<Pool>>() // Make sure Pool is the type of your Redis connection pool
        .ok_or_else(|| ServiceError::general(&req, "Failed to extract Redis pool", true))?;

    let mut con = redis_pool.get().await.unwrap();
    // Delete all session tokens associated with the user
    con.del(user.to_string()).await?;
    Ok(true)
}

pub async fn try_remove_active_session_token(req: &HttpRequest) -> Result<bool, ServiceError> {
    let redis_pool = req
        .app_data::<web::Data<Pool>>() // Make sure Pool is the type of your Redis connection pool
        .ok_or_else(|| ServiceError::general(&req, "Failed to extract Redis pool", true))?;

    if let Some(token) = get_session_token_http_request(req) {
        if let Ok(decoded_data) = decode_token(&token) {
            // Get a Redis connection from the pool
            let mut con = redis_pool.get().await.unwrap();

            let user = decoded_data.claims.user_id.to_string();
            let session_id = decoded_data.claims.session_id.to_string();

            // Remove the specific session token for the user
            con.hdel(&user, &session_id).await.map_err(|e| {
                ServiceError::general(
                    req,
                    format!("Failed to remove session token from Redis: {}", e),
                    false,
                )
            })?;

            return Ok(true);
        }
    }

    Err(ServiceError::not_found(
        &req,
        "Error logout from current session".to_string(),
        true,
    ))
}

pub fn get_ip_addr(req: &HttpRequest) -> Result<String, ServerError> {
    Ok(req
        .peer_addr()
        .ok_or(err_server!("Get ip address error"))?
        .ip()
        .to_string())
}

pub fn get_user_agent(req: &HttpRequest) -> String {
    return if let Some(user_agent) = req.headers().get("user-agent") {
        user_agent.to_str().unwrap_or("Unknown").to_string()
    } else {
        "".to_string()
    };
}

//System func for administration bd
pub async fn delete_all_expired_user_tokens(
    req: HttpRequest,
    user: &str,
) -> Result<bool, ServiceError> {
    let redis_pool = req
        .app_data::<web::Data<Pool>>()
        .ok_or_else(|| ServiceError::general(&req, "Failed to extract Redis pool", true))?;

    let now = Utc::now();
    let mut con = redis_pool.get().await.map_err(|e| {
        ServiceError::general(&req, format!("Failed to get Redis connection: {}", e), true)
    })?;

    let tokens: HashMap<String, String> = con.hgetall(user.to_string()).await.map_err(|e| {
        ServiceError::general(
            &req,
            format!("Failed to fetch tokens from Redis: {}", e),
            true,
        )
    })?;

    for token in tokens.values() {
        if let Ok(decoded_data) = decode_token(token) {
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime < now {
                con.hdel(
                    &decoded_data.claims.user_id,
                    &decoded_data.claims.session_id,
                )
                    .await
                    .map_err(|e| {
                        ServiceError::general(
                            &req,
                            format!("Failed to delete expired token from Redis: {}", e),
                            true,
                        )
                    })?;
            }
        }
    }

    Ok(true)
}
