use actix_web::{web, HttpRequest};
use base32;
use bip39::{Language, Mnemonic};
use chrono::Utc;
use entity::user;
use entity::user_security_settings;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection, IntoActiveModel};
use url::Url;

use crate::models::ServiceError;
use crate::modules::auth::credentials::{
    credential_validator, generate_password_hash, validate_email_rules, validate_password_rules,
};
use crate::modules::auth::email::send_validate_email;
use crate::modules::auth::service::{
    get_user_by_email, get_user_by_id, get_user_security_token_by_id, get_user_settings_by_id,
};
use crate::modules::user::models::{
    AboutMeInformation, AuthenticationAppInformation, ChangeEmailParams, ChangePasswordParams,
    MnemonicConfirmation, SecuritySettingsUpdate,
};

pub async fn try_about_me(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<AboutMeInformation, ServiceError> {
    let db = db.get_ref();
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

    return Err(ServiceError::bad_request(
        &req,
        "User not found.".to_string(),
        true,
    ));
}

pub async fn try_change_email(
    req: &HttpRequest,
    user_id: &str,
    params: ChangeEmailParams,
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
    if &params.new_email != &params.new_email_confirm {
        return Err(ServiceError::bad_request(
            &req,
            "Re-enter new email and confirm email.".to_string(),
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

    if let Some(user) = get_user_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
            return Err(ServiceError::bad_request(
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
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
    // Check the password is valid
    if let Err(e) = validate_password_rules(&params.new_password, &params.new_password_confirm) {
        return Err(ServiceError::bad_request(&req, format!("{}", e), true));
    }
    if let Some(user) = get_user_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        if !credential_validator(&user, &params.current_password).map_err(|e| e.general(&req))? {
            return Err(ServiceError::bad_request(
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

pub async fn try_resend_verify_email(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
    if let Some(user) = get_user_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?
    {
        return if user.email_validated {
            Err(ServiceError::bad_request(
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

    return Err(ServiceError::bad_request(
        &req,
        "User not found.".to_string(),
        true,
    ));
}

// Security Settings

pub async fn try_get_security_settings(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<user_security_settings::Model, ServiceError> {
    let db = db.get_ref();
    get_security_settings(req, user_id, db).await
}

pub async fn get_security_settings(
    req: &HttpRequest,
    user_id: &str,
    db: &DatabaseConnection,
) -> Result<user_security_settings::Model, ServiceError> {
    let settings = get_user_settings_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?;
    Ok(settings)
}

pub async fn try_update_security_settings(
    req: &HttpRequest,
    user_id: &str,
    params: SecuritySettingsUpdate,
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
    return Err(ServiceError::bad_request(
        &req,
        "User not found.".to_string(),
        true,
    ));
}

// 2FA

pub async fn try_add_email_2fa(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
    toggle_email(req, user_id, true, db).await
}

pub async fn try_remove_email_2fa(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
    toggle_email(req, user_id, false, db).await
}

pub async fn try_2fa_add(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<AuthenticationAppInformation, ServiceError> {
    let db = db.get_ref();
    generate_2fa_secret(req, user_id, db).await
}

pub async fn try_2fa_activate(
    req: &HttpRequest,
    user_id: &str,
    params: MnemonicConfirmation,
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
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
            Err(ServiceError::bad_request(
                &req,
                "Wrong mnemonic phrase".to_string(),
                true,
            ))
        };
    }

    return Err(ServiceError::bad_request(
        &req,
        "Error validate mnemonic".to_string(),
        true,
    ));
}

pub async fn try_2fa_reset(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<AuthenticationAppInformation, ServiceError> {
    let db = db.get_ref();
    generate_2fa_secret(req, user_id, db).await
}

pub async fn try_2fa_remove(
    req: &HttpRequest,
    user_id: &str,
    db: web::Data<DatabaseConnection>,
) -> Result<(), ServiceError> {
    let db = db.get_ref();
    let settings = get_user_settings_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?;
    let mut settings = settings.into_active_model();
    settings.two_factor_authenticator_app = Set(false);
    settings.update(db).await?;
    Ok(())
}

async fn toggle_email(
    req: &HttpRequest,
    user_id: &str,
    two_factor: bool,
    db: &DatabaseConnection,
) -> Result<(), ServiceError> {
    let settings = get_security_settings(req, user_id, db).await?;
    let mut settings = settings.into_active_model();
    settings.two_factor_email = Set(two_factor);
    settings.update(db).await?;
    Ok(())
}

/// need refactoring to valid google app scheme?
pub fn generate_totp_uri(secret: &str, user_id: &str, issuer: &str) -> String {
    let mut url = Url::parse("otpauth://totp/").unwrap();
    url.path_segments_mut()
        .unwrap()
        .push(&format!("{}:{}", issuer, user_id));

    url.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", "30");

    url.to_string()
}

async fn generate_2fa_secret(
    req: &HttpRequest,
    user_id: &str,
    db: &DatabaseConnection,
) -> Result<AuthenticationAppInformation, ServiceError> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).expect("Failed to fill bytes with randomness");
    let mnemonic = Mnemonic::from_entropy(&secret, Language::English).unwrap();
    let mnemonic = mnemonic.phrase().to_string();
    let base32_secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret);
    let url = generate_totp_uri(&base32_secret, user_id, "Arzamas"); //not impl yet

    let otp_token = get_user_security_token_by_id(user_id, db)
        .await
        .map_err(|s| s.general(&req))?;

    let mut otp_token = otp_token.into_active_model();
    otp_token.otp_app_hash = Set(Some(base32_secret.clone()));
    otp_token.otp_app_mnemonic = Set(Some(mnemonic.clone()));
    otp_token.update(db).await?;

    let json = AuthenticationAppInformation {
        mnemonic,
        base32_secret,
    };

    Ok(json)
}
