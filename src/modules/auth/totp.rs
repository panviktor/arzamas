use crate::core::db::DB;
use crate::core::redis::REDIS_CLIENT;
use chrono::{Duration, Utc};
use entity::user_otp_token;
use entity::user_security_settings;
use redis::AsyncCommands;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::err_server;
use crate::models::ServerError;
use crate::modules::auth::email::send_totp_email_code;
use crate::modules::auth::hash_token;
use crate::modules::auth::service::block_user_until;
use crate::modules::auth::session::{decode_token, generate_token};

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
        expiry.timestamp_nanos(),
    )
    .map_err(|e| err_server!("Unable to generate session token.:{}", e))?;

    let db = &*DB;
    if let Some(user) = user_otp_token::Entity::find()
        .filter(user_otp_token::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?
    {
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

pub async fn verify_otp_codes(
    email_code: Option<&str>,
    app_code: Option<&str>,
    user_id: &str,
    login_ip: &str,
) -> Result<String, ServerError> {
    let db = &*DB;

    let user_settings = user_security_settings::Entity::find()
        .filter(user_security_settings::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?;

    if user_settings.is_none() {
        return Err(err_server!(
            "No security settings found for user id {}",
            user_id
        ));
    }

    let user_settings = user_settings.unwrap();

    let user_otp_token = user_otp_token::Entity::find()
        .filter(user_otp_token::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?;

    if user_otp_token.is_none() {
        return Err(err_server!(
            "No security settings found for user id {}",
            user_id
        ));
    }

    let user_otp_token = user_otp_token.unwrap();

    match (
        user_settings.two_factor_email,
        user_settings.two_factor_authenticator_app,
    ) {
        (true, true) => {
            if email_code.is_none() || app_code.is_none() {
                return Err(err_server!(
                    "No  2fa auth code found for user id {}",
                    user_id
                ));
            }

            // validate email, validate otp set ok/false attempt_count,
        }
        (true, false) => {
            if email_code.is_none() {
                return Err(err_server!(
                    "No 2fa auth code found for user id {}",
                    user_id
                ));
            }

            let email_code = email_code.unwrap();

            if user_otp_token.expiry > Utc::now().naive_utc() && user_otp_token.attempt_count > 4 {
                block_user_until(user_id, Utc::now() + Duration::minutes(15)).await?;

                user_otp_token.delete(db).await.map_err(|e| {
                    err_server!("Problem delete OTP token for user {}: {}", user_id, e)
                })?;
                return Err(err_server!("Invalid OTP Code, try again"));
            };

            let hash = hash_token(email_code);

            if user_otp_token.code != hash {
                let user_attempt_count = user_otp_token.attempt_count;
                let mut new_user: user_otp_token::ActiveModel = user_otp_token.into();
                new_user.attempt_count = Set(user_attempt_count + 1);
                new_user
                    .update(db)
                    .await
                    .map_err(|e| err_server!("Problem updating OTP token {}:{}", user_id, e))?;
                return Err(err_server!("Invalid OTP Code, try again"));
            }

            if let Ok(decoded_data) = decode_token(&user_otp_token.otp_hash) {
                let token = decoded_data.claims;
                let hash = user_otp_token.otp_hash.clone();

                let mut client = REDIS_CLIENT.get_async_connection().await?;
                client.hset(token.user_id, token.session_id, &hash).await?;

                user_otp_token.delete(db).await.map_err(|e| {
                    err_server!("Problem delete OTP token for user {}: {}", user_id, e)
                })?;
                if token.login_ip == login_ip {
                    return Ok(hash);
                }
            }
        }
        (false, true) => {
            if app_code.is_none() {
                return Err(err_server!(
                    "No  2fa auth code found for user id {}",
                    user_id
                ));
            }

            //  validate otp set ok/false attempt_count,
        }
        (false, false) => {
            return Err(err_server!("Neither email code nor app code is enabled"));
        }
    }

    Err(err_server!("Invalid OTP Code."))
}
