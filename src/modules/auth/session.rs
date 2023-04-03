use actix_http::header::HeaderValue;
use actix_web::dev::ServiceRequest;
use actix_web::HttpRequest;
use chrono::{Duration, TimeZone, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use std::collections::HashMap;
use std::option::Option;
use uuid::Uuid;

use crate::core::config::APP_SETTINGS;
use crate::core::constants::core_constants;
use crate::core::constants::emojis::EMOJIS;

use crate::core::redis::REDIS_CLIENT;
use crate::err_server;
use crate::models::{ServerError, ServiceError};
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
    let now = Utc::now().timestamp_nanos();

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
) -> Result<String, ServerError> {
    let expiry = match persistent {
        false => Utc::now() + Duration::days(1),
        true => Utc::now() + Duration::days(7),
    };

    let login_session = Uuid::new_v4().to_string();
    let token = generate_token(
        user,
        &login_session,
        login_ip,
        user_agent,
        expiry.timestamp_nanos(),
    );

    let token_to_redis =
        token.map_err(|e| err_server!("Unable to generate session token.:{}", e))?;
    let mut client = REDIS_CLIENT.get_async_connection().await?;
    client
        .hset(user.to_string(), &login_session, &token_to_redis)
        .await?;
    Ok(token_to_redis)
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
pub async fn validate_session(token_from_req: &str) -> Result<Option<String>, ServerError> {
    if let Ok(decoded_data) = decode_token(token_from_req) {
        let mut con = REDIS_CLIENT.get_async_connection().await?;
        let user = decoded_data.claims.user_id.to_string();
        let session_id = decoded_data.claims.session_id.to_string();
        let token_from_redis: String = con.hget(user.to_owned(), session_id).await?;

        if token_from_redis == token_from_req {
            let now = Utc::now();
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime > now {
                return Ok(Some(user));
            } else {
                let token = decoded_data.claims;
                con.hdel(&token.user_id, token.session_id).await?;
            }
        }
    }
    Ok(None)
}

async fn valid_sessions(tokens: Vec<String>) -> Result<Vec<UserToken>, ServerError> {
    let now = Utc::now();
    let mut valid_tokens: Vec<UserToken> = vec![];
    let mut con = REDIS_CLIENT.get_async_connection().await?;

    for token in tokens.iter() {
        if let Ok(decoded_data) = decode_token(token) {
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime > now {
                let token = decoded_data.claims;
                valid_tokens.push(token)
            } else {
                let token = decoded_data.claims;
                con.hdel(&token.user_id, token.session_id).await?;
            }
        }
    }
    Ok(valid_tokens)
}

pub async fn try_active_sessions(
    req: &HttpRequest,
    user: &str,
) -> Result<Vec<UserToken>, ServiceError> {
    let mut client = REDIS_CLIENT.get_async_connection().await?;
    let tokens: HashMap<String, String> = client.hgetall(user.to_string()).await?;
    let tokens = tokens.values().cloned().collect();

    valid_sessions(tokens).await.map_err(|e| e.general(&(req)))
}

pub async fn try_current_active_session(req: &HttpRequest) -> Result<UserToken, ServiceError> {
    if let Some(token) = get_session_token_http_request(req) {
        if let Ok(decoded_data) = decode_token(&token) {
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            let now = Utc::now();

            if datetime > now {
                let mut con = REDIS_CLIENT.get_async_connection().await?;
                let user = decoded_data.claims.user_id.to_string();
                let session_id = decoded_data.claims.session_id.to_string();
                let token_from_redis: String = con.hget(user.to_owned(), session_id).await?;

                if token_from_redis == token {
                    return Ok(decoded_data.claims);
                }
            }
        }
    }
    Err(ServiceError::not_found(
        &req,
        "Error get session token http request".to_string(),
        false,
    ))
}

pub async fn try_remove_all_sessions_token(user: &str) -> Result<bool, ServiceError> {
    let mut con = REDIS_CLIENT.get_async_connection().await?;
    con.del(user.to_string()).await?;
    Ok(true)
}

pub async fn try_remove_active_session_token(req: &HttpRequest) -> Result<bool, ServiceError> {
    if let Some(token) = get_session_token_http_request(req) {
        if let Ok(decoded_data) = decode_token(&token) {
            let mut con = REDIS_CLIENT.get_async_connection().await?;
            let user = decoded_data.claims.user_id.to_string();
            let session_id = decoded_data.claims.session_id.to_string();
            con.hdel(user, session_id).await?;
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
pub async fn delete_all_expired_user_tokens(user: &str) -> Result<bool, ServiceError> {
    let now = Utc::now();
    let mut con = REDIS_CLIENT.get_async_connection().await?;
    let tokens: HashMap<String, String> = con.hgetall(user.to_string()).await?;
    let tokens: Vec<String> = tokens.values().cloned().collect();
    for token in tokens.iter() {
        if let Ok(decoded_data) = decode_token(token) {
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime < now {
                let token = decoded_data.claims;
                con.hdel(&token.user_id, token.session_id).await?;
            }
        }
    }
    Ok(true)
}
