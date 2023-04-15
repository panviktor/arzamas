use actix_web::HttpRequest;
use chrono::Utc;
use entity::user;
use entity::user_security_settings;
use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::Set;

use crate::core::db::DB;
use crate::err_server;
use crate::models::{ServerError, ServiceError};
use crate::modules::auth::credentials::{
    credential_validator, generate_password_hash, validate_email_rules, validate_password_rules,
};
use crate::modules::auth::email::send_validate_email;
use crate::modules::auth::service::{get_user_by_email, get_user_by_id, get_user_settings_by_id};
use crate::modules::user::models::{AboutMeInformation, ChangeEmailParams, ChangePasswordParams};

pub async fn try_about_me(
    req: &HttpRequest,
    user_id: &str,
) -> Result<AboutMeInformation, ServiceError> {
    if let Some(user) = get_user_by_id(user_id).await.map_err(|s| s.general(&req))? {
        return Ok(AboutMeInformation {
            name: user.username,
            email: user.email,
            email_validated: user.email_validated,
        });
    }

    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

pub async fn try_change_email(
    req: &HttpRequest,
    user_id: &str,
    params: ChangeEmailParams,
) -> Result<(), ServiceError> {
    if &params.new_email != &params.new_email_confirm {
        return Err(ServiceError::bad_request(
            &req,
            format!("Re-enter new email and confirm email.",),
            true,
        ));
    }

    // Check the email is valid
    if let Err(e) = validate_email_rules(&params.new_email) {
        return Err(ServiceError::bad_request(
            &req,
            format!("New email: {}", e),
            true,
        ));
    }

    if let Some(user) = get_user_by_id(user_id).await.map_err(|s| s.general(&req))? {
        if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
            return Err(ServiceError::bad_request(
                &req,
                "Invalid current password",
                true,
            ));
        }

        if let Some(email_user) = get_user_by_email(&params.new_email)
            .await
            .map_err(|s| s.general(&req))?
        {
            println!("user with email find");
            if email_user.id != user.id {
                println!("this email from different user");
            } else {
                println!("Old email address and new email address are equal.");
                // Send to old email alert
            }
        } else {
            // Send a validation email
            send_validate_email(&user.user_id, &params.new_email, true)
                .await
                .map_err(|s| s.general(&req))?;

            let db = &*DB;
            let mut active: user::ActiveModel = user.into();
            active.email = Set(params.new_email.to_owned());
            active.updated_at = Set(Utc::now().naive_utc());
            active.email_validated = Set(false);
            active.update(db).await?;

            // Add optional invalidate all user session
            // based on user preferences
            // Send to new email confirmation to validation
        }
    }
    Ok(())
}

pub async fn try_change_password(
    req: &HttpRequest,
    user_id: &str,
    params: ChangePasswordParams,
) -> Result<(), ServiceError> {
    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.new_password, &params.new_password_confirm) {
        return Err(ServiceError::bad_request(&req, format!("{}", e), true));
    }
    if let Some(user) = get_user_by_id(user_id).await.map_err(|s| s.general(&req))? {
        if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
            return Err(ServiceError::bad_request(
                &req,
                "Invalid current password",
                true,
            ));
        }

        let db = &*DB;
        let hash = generate_password_hash(&params.new_password).map_err(|s| s.general(&req))?;
        let mut active: user::ActiveModel = user.into();
        active.pass_hash = Set(hash.to_owned());
        active.updated_at = Set(Utc::now().naive_utc());
        active.update(db).await?;

        // Add optional invalidate all user session
        // based on user preferences
        // Send to email alert
    }
    Ok(())
}

pub async fn try_resend_verify_email(req: &HttpRequest, user_id: &str) -> Result<(), ServiceError> {
    if let Some(user) = get_user_by_id(user_id).await.map_err(|s| s.general(&req))? {
        return if user.email_validated {
            Err(ServiceError::bad_request(
                &req,
                format!("Email already activated."),
                true,
            ))
        } else {
            send_validate_email(&user.user_id, &user.email, true)
                .await
                .map_err(|s| s.general(&req))?;
            Ok(())
        };
    }

    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

// Security Settings

pub async fn try_get_security_settings(
    req: &HttpRequest,
    user_id: &str,
) -> Result<user_security_settings::Model, ServiceError> {
    let settings = get_user_settings_by_id(user_id)
        .await
        .map_err(|s| s.general(&req))?;
    Ok(settings)
}

pub async fn try_update_security_settings(
    req: &HttpRequest,
    user_id: &str,
) -> Result<(), ServiceError> {
    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

// 2FA

pub async fn try_add_email_2fa(req: &HttpRequest, user_id: &str) -> Result<(), ServiceError> {
    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

pub async fn try_remove_email_2fa(req: &HttpRequest, user_id: &str) -> Result<(), ServiceError> {
    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

pub async fn try_2fa_add(req: &HttpRequest, user_id: &str) -> Result<(), ServiceError> {
    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

pub async fn try_2fa_reset(req: &HttpRequest, user_id: &str) -> Result<(), ServiceError> {
    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

pub async fn try_2fa_remove(req: &HttpRequest, user_id: &str) -> Result<(), ServiceError> {
    return Err(ServiceError::bad_request(
        &req,
        format!("User not found."),
        true,
    ));
}

/// Generate 10 TOTP backup codes.
fn generate_totp_backup_codes() -> Result<Vec<String>, ServerError> {
    let mut backup_codes: Vec<String> = vec![];
    for _ in 0..10 {
        let mut token = [0u8; 16];
        getrandom::getrandom(&mut token)
            .map_err(|e| err_server!("Error generating token: {}", e))?;
        backup_codes.push(hex::encode(token.to_vec()));
    }
    Ok(backup_codes)
}
