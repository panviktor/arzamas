use std::collections::HashMap;
use actix_web::dev::ServiceRequest;
use chrono::{ Duration, TimeZone, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use redis::AsyncCommands;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::option::Option;
use actix_http::header::HeaderValue;
use actix_web::HttpRequest;
use sea_orm::ColIdx;
use uuid::Uuid;

use crate::core::config::APP_SETTINGS;
use crate::core::constants::core_constants;
use crate::core::constants::emojis::EMOJIS;

use crate::core::redis::REDIS_CLIENT;
use crate::err_server;
use crate::models::{ServerError, ServiceError};

#[derive(Serialize, Deserialize)]
pub struct UserToken {
    // issued at
    pub iat: i64,
    // expiration
    pub exp: i64,
    // data
    pub user_id: String,
    // session
    pub session_id: String,
    // random session name
    pub session_name: String,
    // login ip
    pub login_ip: String,
    // User-Agent
    pub user_agent: String,
}

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
    ).map_err(|e| err_server!("Unable to generate session token.:{}", e))?;

    Ok(result)
}

// Create a session token for a specific user
pub async fn generate_session_token(
    user: &str,
    persistent: bool,
    login_ip: &str,
    user_agent: &str
) -> Result<String, ServerError> {
    let expiry = match persistent {
        false => Utc::now() + Duration::days(1),
        true => Utc::now() + Duration::days(30),
    };

    let login_session = Uuid::new_v4().to_string();
    let token = generate_token(
        user,
        &login_session,
        login_ip,
        user_agent,
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
            return Some(token.to_string())
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
                println!("{}", decoded_data.claims.session_name);
                return Ok(Some(user));
            }
        }
    }
    Ok(None)
}

fn valid_sessions_count(tokens: Vec<String>) -> Result<i32, ServerError> {
    let now = Utc::now();
    let mut valid_token_count = 0;

    for token in tokens.iter() {
        if let Ok(decoded_data) = decode_token(token) {
            let datetime = Utc.timestamp_nanos(decoded_data.claims.exp);
            if datetime > now {
                valid_token_count += 1
            }
        }
    }

    Ok(valid_token_count)
}

pub async fn sessions_active_count(
    req: &HttpRequest,
    user: &str
) -> Result<HashMap<String, String>, ServiceError> {
    let mut client = REDIS_CLIENT.get_async_connection().await?;
    let str: HashMap<String, String> = client.hgetall(user.to_string()).await?;
    let tokens = str.values().cloned().collect();

    let count = valid_sessions_count(tokens)
        .map_err(|e| e.general(&(req)));
    println!("Valid sessions: {}", count.unwrap_or(0));

    if let Some(current_token) = get_session_token_http_request(&req) {
           let dec = decode_token(&current_token.as_str());
        match dec {
            Ok(token) => {

                println!("{}",token.claims.user_agent);
                println!("{}",token.claims.session_name);
                println!("{}",token.claims.login_ip);

            }
            Err(_) => {}
        }
    }

    let mut valid = 0;
    let mut invalid = 0;









    // if let Some(token) =  get_session_token_http_request() {
    //
    //
    // }

    Ok(str)
}

//
// pub async fn remove_session_token(
//     user: &str
// ) -> Result<Bool, ServerError> {
//     let mut client = REDIS_CLIENT.get_async_connection().await?;
//     // client.hdel(user.to_string(), &login_session, &token_to_redis).await?;
//
//     Ok(true)
// }
//
// pub async fn remove_all_sessions_token(
//     user: &str
// ) -> Result<Bool, ServerError> {
//     let mut client = REDIS_CLIENT.get_async_connection().await?;
//     // client.hdel(user.to_string(), &login_session, &token_to_redis).await?;
//
//     Ok(true)
// }

pub fn get_ip_addr(req: &HttpRequest) -> Result<String, ServerError> {
    Ok(req
        .peer_addr()
        .ok_or(err_server!("Get ip address error"))?
        .ip()
        .to_string()
    )
}

pub fn get_user_agent(req: &HttpRequest) -> &str {
    return if let Some(user_agent) = req.headers().get("user-agent") {
        user_agent.to_str().unwrap_or("Unknown")
    } else {
        ""
    }
}