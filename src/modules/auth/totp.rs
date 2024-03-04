use chrono::{Duration, Utc};
use deadpool_redis::Pool;
use entity::user_otp_token;
use entity::user_security_settings;
use redis::AsyncCommands;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter, Set,
};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use crate::err_server;
use crate::core::error::ServerError;

use crate::modules::auth::email::send_totp_email_code;
use crate::modules::auth::hash_token;
use crate::modules::auth::session::{decode_token, generate_token};
use crate::modules::auth::utils::{
    block_user_until, get_user_security_token_by_id, set_attempt_count,
};

pub async fn set_app_only_expire_time(
    user_id: &str,
    persistent: bool,
    login_ip: &str,
    user_agent: &str,
    db: &DatabaseConnection,
) -> Result<(), ServerError> {
    let expiry = match persistent {
        false => Utc::now() + Duration::days(1),
        true => Utc::now() + Duration::days(7),
    };

    let expiry_timestamp_nanos = expiry
        .timestamp_nanos_opt()
        .ok_or_else(|| err_server!("Failed to get nanosecond timestamp"))?;

    let code_expiration = Utc::now() + Duration::minutes(3);
    let login_session = Uuid::new_v4().to_string();

    let totp_token = generate_token(
        user_id,
        &login_session,
        login_ip,
        user_agent,
        expiry_timestamp_nanos,
    )
        .map_err(|e| err_server!("Unable to generate session token.:{}", e))?;

    if let Some(user) = user_otp_token::Entity::find()
        .filter(user_otp_token::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?
    {
        let mut active: user_otp_token::ActiveModel = user.into();
        active.otp_email_hash = Set(Some(totp_token));
        active.expiry = Set(Some(code_expiration.naive_utc()));
        active.attempt_count = Set(0);
        active
            .update(db)
            .await
            .map_err(|e| err_server!("Problem updating user OTP data {}:{}", user_id, e))?;
        return Ok(());
    }
    return Err(err_server!("User not found!"));
}

pub async fn generate_email_code(
    user_id: &str,
    persistent: bool,
    email: &str,
    login_ip: &str,
    user_agent: &str,
    db: &DatabaseConnection,
) -> Result<(), ServerError> {
    let expiry = match persistent {
        false => Utc::now() + Duration::days(1),
        true => Utc::now() + Duration::days(7),
    };

    let expiry_timestamp_nanos = expiry
        .timestamp_nanos_opt()
        .ok_or_else(|| err_server!("Failed to get nanosecond timestamp"))?;

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
        expiry_timestamp_nanos,
    )
        .map_err(|e| err_server!("Unable to generate session token.:{}", e))?;

    if let Some(user) = user_otp_token::Entity::find()
        .filter(user_otp_token::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?
    {
        let mut active: user_otp_token::ActiveModel = user.into();
        active.otp_email_hash = Set(Some(totp_token));
        active.expiry = Set(Some(code_expiration.naive_utc()));
        active.attempt_count = Set(0);
        active.code = Set(Some(hash));
        active
            .update(db)
            .await
            .map_err(|e| err_server!("Problem updating user OTP data {}:{}", user_id, e))?;
        send_totp_email_code(email, &code, user_id).await?;
        return Ok(());
    }
    return Err(err_server!("User not found!"));
}

pub async fn verify_otp_codes(
    email_code: Option<&str>,
    app_code: Option<&str>,
    user_id: &str,
    login_ip: &str,
    db: &DatabaseConnection,
    redis_pool: &Pool,
) -> Result<String, ServerError> {
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
            "No available security settings found for user id {}",
            user_id
        ));
    }

    let user_otp_token = user_otp_token.unwrap();

    return match (
        user_settings.two_factor_email,
        user_settings.two_factor_authenticator_app,
    ) {
        (true, true) => {
            if email_code.is_none() || app_code.is_none() {
                return Err(err_server!(
                    "No 2fa auth codes found for user id {}",
                    user_id
                ));
            }

            let user_otp_token = validate_email_otp(user_otp_token, email_code, db).await?;
            let user_otp_token = validate_app_code(user_otp_token, app_code, user_id, db).await?;
            let token = validate_ip(user_otp_token, login_ip, &redis_pool).await?;
            Ok(token)
        }
        (true, false) => {
            let user_otp_token = validate_email_otp(user_otp_token, email_code, db).await?;
            let token = validate_ip(user_otp_token, login_ip, &redis_pool).await?;
            Ok(token)
        }
        (false, true) => {
            if app_code.is_none() {
                return Err(err_server!(
                    "No 2fa auth app-code found for user id {}",
                    user_id
                ));
            }
            let user_otp_token = validate_app_code(user_otp_token, app_code, user_id, db).await?;
            let token = validate_ip(user_otp_token, login_ip, &redis_pool).await?;
            Ok(token)
        }
        (false, false) => Err(err_server!("Neither email code nor app code is enabled")),
    };
}

async fn validate_email_otp(
    user_otp_token: user_otp_token::Model,
    email_code: Option<&str>,
    db: &DatabaseConnection,
) -> Result<user_otp_token::Model, ServerError> {
    if email_code.is_none() {
        return Err(err_server!(
            "No 2fa auth code found for user id {}",
            user_otp_token.user_id
        ));
    }
    let email_code = email_code.unwrap();

    if user_otp_token.attempt_count >= 4 {
        return Err(err_server!("Too many attempts ..."));
    }

    if let Some(expiry) = user_otp_token.expiry {
        if expiry < Utc::now().naive_utc() {
            block_user_until(
                &user_otp_token.user_id,
                Utc::now() + Duration::minutes(15),
                db,
            )
                .await?;
            let user_id = user_otp_token.user_id.clone();

            user_otp_token
                .delete(db)
                .await
                .map_err(|e| err_server!("Problem delete OTP token for user {}: {}", user_id, e))?;

            return Err(err_server!("Invalid OTP Code, try login again"));
        }
    } else {
        return Err(err_server!("Invalid Expiry Token, try login again"));
    }

    let hash = hash_token(email_code);

    if let Some(code) = user_otp_token.code.clone() {
        if code != hash {
            let new_count = user_otp_token.attempt_count + 1;
            let user_id = user_otp_token.user_id.clone();
            let new_user: user_otp_token::ActiveModel = user_otp_token.into();
            set_attempt_count(new_count, &user_id, new_user, db).await?;

            return Err(err_server!("Invalid OTP Code, try again"));
        } else {
            Ok(user_otp_token)
        }
    } else {
        return Err(err_server!("Invalid Expiry Token, try login again"));
    }
}

async fn validate_app_code(
    user_otp_token: user_otp_token::Model,
    app_code: Option<&str>,
    user_id: &str,
    db: &DatabaseConnection,
) -> Result<user_otp_token::Model, ServerError> {
    return match app_code {
        None => {
            let error_message = format!("No 2FA auth app-code found for user id {}", user_id);
            Err(err_server!("{}", error_message))
        }
        Some(code) => {
            if user_otp_token.attempt_count >= 4 {
                return Err(err_server!("Too many attempts ..."));
            }

            return if let Some(expiry) = user_otp_token.expiry {
                if expiry < Utc::now().naive_utc() {
                    block_user_until(
                        &user_otp_token.user_id,
                        Utc::now() + Duration::minutes(15),
                        db,
                    )
                        .await?;
                    let user_id = user_otp_token.user_id.clone();

                    user_otp_token.delete(db).await.map_err(|e| {
                        err_server!("Problem delete OTP token for user {}: {}", user_id, e)
                    })?;

                    return Err(err_server!("Invalid date for OTP code, try login again!!"));
                }

                return if let Ok(_) = generate_app_code(user_id, code, db).await {
                    Ok(user_otp_token)
                } else {
                    let new_count = user_otp_token.attempt_count + 1;
                    let user_id = user_otp_token.user_id.clone();
                    let new_user: user_otp_token::ActiveModel = user_otp_token.into();
                    set_attempt_count(new_count, &user_id, new_user, db).await?;

                    Err(err_server!("Invalid OTP Code, try again, need new login!"))
                };
            } else {
                Err(err_server!("Invalid Expiry Token, try login again!"))
            };
        }
    };
}

async fn generate_app_code(
    user_id: &str,
    code: &str,
    db: &DatabaseConnection,
) -> Result<(), ServerError> {
    let otp_token = get_user_security_token_by_id(user_id, db).await?;
    if let Some(saved_hash) = otp_token.otp_app_hash {
        ///
        ///
        /// all try mnemonic!
        ///
        ///
        verify_totp(&saved_hash, code)
    } else {
        Err(err_server!("Hash not found, try login again!?"))
    }
}

async fn validate_ip(
    user_otp_token: user_otp_token::Model,
    ip: &str,
    redis_pool: &Pool,
) -> Result<String, ServerError> {
    if let Some(otp_email_hash) = user_otp_token.otp_email_hash.as_ref() {
        if let Ok(decoded_data) = decode_token(&otp_email_hash) {
            let token = decoded_data.claims;
            let mut conn = redis_pool
                .get()
                .await
                .map_err(|e| err_server!("{}", format!("Failed to get Redis connection: {}", e)))?;

            conn.hset(token.user_id, token.session_id, otp_email_hash)
                .await
                .map_err(|e| err_server!("{}", format!("Failed to set value in Redis: {}", e)))?;

            return if token.login_ip == ip {
                Ok(otp_email_hash.to_string())
            } else {
                Err(err_server!("Your IP has changed"))
            };
        }
    }
    Err(err_server!("Invalid OTP Code."))
}

pub fn verify_totp(secret: &str, token: &str) -> Result<(), ServerError> {
    if let Ok(secret) = Secret::Encoded(secret.to_string()).to_bytes() {
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret)
            .map_err(|e| err_server!("Failed to create TOTP: {}", e))?;
        if let Ok(res) = totp.check_current(token) {
            if res {
                return Ok(());
            }
        }
    }
    Err(err_server!("Invalid OTP Code!*"))
}
