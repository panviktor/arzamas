use actix_web::dev::ServiceRequest;
use chrono::{ Duration, TimeZone, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::option::Option;
use uuid::Uuid;

use crate::core::config::APP_SETTINGS;
use crate::core::constants;
use crate::core::redis::REDIS_CLIENT;
use crate::err_server;
use crate::models::{ServerError, };

#[derive(Serialize, Deserialize)]
pub struct UserToken {
    // issued at
    pub iat: i64,
    // expiration
    pub exp: i64,
    // data
    pub user_id: String,
    pub login_session_id: String,
}

pub fn generate_token(
    user: &str,
    login_session: &str,
    exp: i64,
) -> Result<String, ServerError> {
    let now = Utc::now().timestamp_nanos();
    let payload = UserToken {
        iat: now,
        exp,
        user_id: user.to_string(),
        login_session_id: login_session.to_string(),
    };

    let result = jsonwebtoken::encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
    ).map_err(|e| err_server!("Unable to generate session token.:{}", e))?;

    Ok(result)
}

// Create a session token for a specific user
pub async fn generate_session_token(
    user: &str,
    persistent: bool,
) -> Result<String, ServerError> {
    let expiry = match persistent {
        false => Utc::now() + Duration::days(1),
        true => Utc::now() + Duration::days(30),
    };

    let login_session = Uuid::new_v4().to_string();
    let token = generate_token(
        user,
        &login_session,
        expiry.timestamp_nanos()
    );

    let token_to_redis = token.map_err(|e| err_server!("Unable to generate session token.:{}", e))?;
    let mut client = REDIS_CLIENT.get_async_connection().await?;
    client.hset(user.to_string(), &login_session, &token_to_redis).await?;
    Ok(token_to_redis)
}

pub fn decode_token(token: &str) -> jsonwebtoken::errors::Result<TokenData<UserToken>> {
    jsonwebtoken::decode::<UserToken>(
        &token,
        &DecodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
        &Validation::default()
    )
}

/// Extract the session token
pub fn get_session_token_service_request(req: &ServiceRequest) -> Option<String> {
    if let Some(authed_header) = req.headers().get(constants::AUTHORIZATION) {
        if let Ok(authed_header_str) = authed_header.to_str() {
            if authed_header_str.starts_with(constants::BEARER) {
                let token = authed_header_str[6..authed_header_str.len()].trim();
                return Some(token.to_string())
            }
        }
    }
    None
}

// pub async fn get_user_id_from(token: &str) -> Option<String> {
//     if let Ok(decoded_data) = decode_token(token) {
//         let user_id = decoded_data.claims.user_id.to_string();
//         return Some(user_id)
//     }
//     None
// }

/// Get username from session token
pub async fn validate_session(token_from_req: &str) -> Result<Option<String>, ServerError> {
    if let Ok(decoded_data) = decode_token(token_from_req) {
        let mut con = REDIS_CLIENT.get_async_connection().await?;
        let user = decoded_data.claims.user_id.to_string();
        let session_id = decoded_data.claims.login_session_id.to_string();
        let token_from_redis: String = con.hget(user.to_owned(), session_id).await?;

        if token_from_redis == token_from_req {
            let now = Utc::now();
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime > now {
                return Ok(Some(user));
            }
        }
    }
    Ok(None)
}