use crate::infrastructure::persistence::db::extract_db_connection;
use actix_web::{web, HttpRequest};
use chrono::Utc;
use entity::user;
use entity::user_security_settings;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection, IntoActiveModel};

use crate::application::error::response_error::AppResponseError;
use crate::modules::auth::credentials::{
    credential_validator, generate_password_hash, validate_email_rules, validate_password_rules,
};
use crate::modules::auth::email::send_validate_email;
use crate::modules::auth::utils::{
    get_user_by_email, get_user_by_id, get_user_security_token_by_id, get_user_settings_by_id,
};
use crate::modules::user::models::{
    AboutMeInformation, AuthenticationAppInformation, ChangeEmailParams, ChangePasswordParams,
    MnemonicConfirmation, SecuritySettingsUpdate,
};

use crate::modules::user::utils::{generate_2fa_secret, get_security_settings, toggle_email};

pub async fn try_about_me(
    req: &HttpRequest,
    user_id: &str,
) -> Result<AboutMeInformation, AppResponseError> {
    let db = extract_db_connection(req)?;

    if let Some(user) = get_user_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        return Ok(AboutMeInformation {
            name: user.username,
            email: user.email,
            email_validated: user.email_validated,
        });
    }

    return Err(AppResponseError::bad_request(
        &req,
        "User not found.".to_string(),
        true,
    ));
}

pub async fn try_change_email(
    req: &HttpRequest,
    user_id: &str,
    params: ChangeEmailParams,
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;

    if &params.new_email != &params.new_email_confirm {
        return Err(AppResponseError::bad_request(
            &req,
            "Re-enter new email and confirm email.".to_string(),
            true,
        ));
    }

    // Check the email is valid
    if let Err(e) = validate_email_rules(&params.new_email) {
        return Err(AppResponseError::bad_request(
            &req,
            format!("New email: {}", e),
            true,
        ));
    }

    if let Some(user) = get_user_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        if !credential_validator(&user.pass_hash, &params.current_password)
            .map_err(|e| e.general(&req))?
        {
            return Err(AppResponseError::bad_request(
                &req,
                "Invalid current password",
                true,
            ));
        }

        if let Some(email_user) = get_user_by_email(&params.new_email, db)
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
            send_validate_email(&user.user_id, &params.new_email, true, db)
                .await
                .map_err(|s| s.general(&req))?;

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
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;

    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.new_password, &params.new_password_confirm) {
        return Err(AppResponseError::bad_request(&req, format!("{}", e), true));
    }
    if let Some(user) = get_user_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        if !credential_validator(&user.pass_hash, &params.current_password)
            .map_err(|e| e.general(&req))?
        {
            return Err(AppResponseError::bad_request(
                &req,
                "Invalid current password",
                true,
            ));
        }

        let hash = generate_password_hash(&params.new_password).map_err(|s| s.general(&req))?;
        let mut active: user::ActiveModel = user.into();
        active.pass_hash = Set(hash.to_owned());
        active.updated_at = Set(Utc::now().naive_utc());
        active.update(db).await?;

        // NEED IMPLEMENT
        // Add optional invalidate all user session
        // based on user preferences
        // Send to email alert
    }
    Ok(())
}

pub async fn try_resend_verify_email(req: &HttpRequest, user_id: &str) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;

    if let Some(user) = get_user_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        return if user.email_validated {
            Err(AppResponseError::bad_request(
                &req,
                "Email already activated.".to_string(),
                true,
            ))
        } else {
            send_validate_email(&user.user_id, &user.email, true, db)
                .await
                .map_err(|s| s.general(&req))?;
            Ok(())
        };
    }

    return Err(AppResponseError::bad_request(
        &req,
        "User not found.".to_string(),
        true,
    ));
}

// Security Settings

pub async fn try_get_security_settings(
    req: &HttpRequest,
    user_id: &str,
) -> Result<user_security_settings::Model, AppResponseError> {
    let db = extract_db_connection(req)?;
    get_security_settings(req, user_id, db).await
}

pub async fn try_update_security_settings(
    req: &HttpRequest,
    user_id: &str,
    params: SecuritySettingsUpdate,
) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;

    return Err(AppResponseError::bad_request(
        &req,
        "User not found.".to_string(),
        true,
    ));
}

// 2FA

pub async fn try_add_email_2fa(req: &HttpRequest, user_id: &str) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;
    toggle_email(req, user_id, true, db).await
}

pub async fn try_remove_email_2fa(req: &HttpRequest, user_id: &str) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;
    toggle_email(req, user_id, false, db).await
}

pub async fn try_2fa_add(
    req: &HttpRequest,
    user_id: &str,
) -> Result<AuthenticationAppInformation, AppResponseError> {
    let db = extract_db_connection(req)?;
    generate_2fa_secret(req, user_id, db).await
}

pub async fn try_2fa_activate(
    req: &HttpRequest,
    user_id: &str,
    params: MnemonicConfirmation,
) -> Result<(), AppResponseError> {
    let db = req
        .app_data::<web::Data<DatabaseConnection>>()
        .ok_or_else(|| AppResponseError::general(&req, "Failed to extract database connection", true))?
        .get_ref();

    let otp_token = get_user_security_token_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?;

    if let Some(mnemonic) = otp_token.otp_app_mnemonic {
        return if mnemonic == params.mnemonic {
            let settings = get_user_settings_by_id(user_id, db)
                .await
                .map_err(|s| s.general(&req))?;
            let mut settings = settings.into_active_model();

            settings.two_factor_authenticator_app = Set(true);
            settings.update(db).await?;
            Ok(())
        } else {
            Err(AppResponseError::bad_request(
                &req,
                "Wrong mnemonic phrase".to_string(),
                true,
            ))
        };
    }

    return Err(AppResponseError::bad_request(
        &req,
        "Error validate mnemonic".to_string(),
        true,
    ));
}

pub async fn try_2fa_reset(
    req: &HttpRequest,
    user_id: &str,
) -> Result<AuthenticationAppInformation, AppResponseError> {
    let db = extract_db_connection(req)?;
    generate_2fa_secret(req, user_id, db).await
}

pub async fn try_2fa_remove(req: &HttpRequest, user_id: &str) -> Result<(), AppResponseError> {
    let db = extract_db_connection(req)?;

    let settings = get_user_settings_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?;
    let mut settings = settings.into_active_model();
    settings.two_factor_authenticator_app = Set(false);
    settings.update(db).await?;
    Ok(())
}
