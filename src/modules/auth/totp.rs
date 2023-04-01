use chrono::{ Duration, Utc};
use redis::AsyncCommands;
use uuid::Uuid;
use sea_orm::{
    ActiveModelTrait,
    EntityTrait,
    QueryFilter,
    ColumnTrait,
    Set,
    ModelTrait
};
use entity::{user_otp_token};
use crate::core::db::DB;
use crate::core::redis::REDIS_CLIENT;

use crate::err_server;
use crate::modules::auth::session::{decode_token, generate_token,};
use crate::models::ServerError;
use crate::modules::auth::{hash_token};
use crate::modules::auth::email::send_totp_email_code;

pub async fn generate_email_code(
    user_id: &str,
    persistent: bool,
    email: &str,
    login_ip: &str,
    user_agent: &str,
) -> Result<(), ServerError> {
    let expiry = match persistent {
        false => Utc::now() + Duration::days(1),
        true => Utc::now() + Duration::days(7),
    };

    let code_expiration = Utc::now() + Duration::minutes(5);
    let login_session = Uuid::new_v4().to_string();

    let code = super::generate_token()
        .map_err(|e| err_server!("Unable to generate session code.:{}", e))?;
    let hash = hash_token(&code);

    let totp_token = generate_token(
        user_id,
        &login_session,
        login_ip,
        user_agent,
        expiry.timestamp_nanos()
    )
        .map_err(|e| err_server!("Unable to generate session token.:{}", e))?;

    let db = &*DB;
    if let Some(user) = user_otp_token::Entity::find()
        .filter(user_otp_token::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))? {

        let mut active: user_otp_token::ActiveModel = user.into();
        active.otp_hash = Set(totp_token);
        active.expiry = Set(expiry.naive_utc());
        active.attempt_count = Set(0);
        active.code = Set(hash);
        active
            .update(db)
            .await
            .map_err(|e| err_server!("Problem updating user OTP data {}:{}", user_id, e))?;
    } else {
        let user = user_otp_token::ActiveModel {
            user_id: Set(user_id.to_string()),
            otp_hash: Set(totp_token),
            expiry: Set(code_expiration.naive_utc()),
            attempt_count: Set(0),
            code: Set(hash),
            ..Default::default()
        }
            .insert(db)
            .await
            .map_err(|e| err_server!("Problem user OTP data {}:{}", user_id, e))?;
    }
    send_totp_email_code(email, &code, user_id).await?;
    Ok(())
}

pub async fn verify_email_otp_code(
    code: &str,
    user_id: &str,
    login_ip: &str,
) -> Result<String, ServerError> {

    let db = &*DB;
    if let Some(user) = user_otp_token::Entity::find()
        .filter(user_otp_token::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))? {

        if user.expiry > Utc::now().naive_utc() && user.attempt_count > 4 {
            user.delete(db)
                .await
                .map_err(|e| err_server!("Problem delete OTP token for user {}: {}", user_id, e))?;
            return Err(err_server!("Invalid OTP Code, try again"))
        };

        let hash = hash_token(code);

        if user.code != hash {
            let user_attempt_count = user.attempt_count;
            let mut new_user: user_otp_token::ActiveModel = user.into();
            new_user.attempt_count = Set( user_attempt_count + 1);
            new_user.update(db)
                .await
                .map_err(|e| err_server!("Problem updating OTP token {}:{}", user_id, e))?;
            return Err(err_server!("Invalid OTP Code, try again"))
        }

        if let Ok(decoded_data) = decode_token(&user.otp_hash) {
            let token = decoded_data.claims;
            let hash = user.otp_hash.clone();

            let mut client = REDIS_CLIENT.get_async_connection().await?;
            client.hset(token.user_id.to_string(), &token.session_id.to_string(), &hash).await?;

            user.delete(db)
                .await
                .map_err(|e| err_server!("Problem delete OTP token for user {}: {}", user_id, e))?;
             if token.login_ip == login_ip {
                 return Ok(hash)
            }
        }
    }
    Err(err_server!("Invalid OTP Code."))
}
