use std::collections::{ HashMap};
use actix_web::dev::ServiceRequest;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tracing::{info};
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

pub fn decode_token(token: String) -> jsonwebtoken::errors::Result<TokenData<UserToken>> {
    jsonwebtoken::decode::<UserToken>(
        &token,
        &DecodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
        &Validation::default()
    )
}

/// Extract the session token
pub fn get_session_token_service_request(req: &ServiceRequest) -> Option<UserToken> {
    if let Some(authed_header) = req.headers().get(constants::AUTHORIZATION) {
        if let Ok(authed_header_str) = authed_header.to_str() {
            if authed_header_str.starts_with(constants::BEARER) {
                let token = authed_header_str[6..authed_header_str.len()].trim();
                if let Ok(token_data) = decode_token(token.to_string()) {
                    info!("Decoding token...");
                    return Some(token_data.claims)
                }
            }
        }
    }
    None
}

/// Get username from session token
pub async fn validate_session(token: &UserToken) -> Result<bool, ServerError> {
    let mut con = REDIS_CLIENT.get_async_connection().await?;

    let user = token.user_id.to_string();
    let tokens: HashMap<String, String> = con.hgetall(user).await?;




    println!("{:?} ", tokens);
    //
    // // let int: isize = con.get("my_key").await?;
    // // println!("{:?}",int);
    // //
    // // let v_int: Vec<isize> = con.mget("my_key").await?;
    // // println!("v {:?}",v_int);

    Ok(true)
}