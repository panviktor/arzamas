use actix_web::HttpRequest;
use chrono::{DateTime, Utc};
use entity::user::Model as User;
use entity::user_security_settings::Model as SecuritySettings;
use entity::{
    user, user_confirmation, user_otp_token, user_restore_password, user_security_settings,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};

use crate::core::db::DB;
use crate::models::{ErrorCode, ServerError, ServiceError};
use crate::modules::auth::credentials::{
    generate_password_hash, validate_email_rules, validate_password_rules, validate_username_rules,
};
use crate::modules::auth::email::send_password_reset_email;
use crate::modules::auth::hash_token;
use crate::modules::auth::models::{
    ForgotPasswordParams, NewUserParams, ResetPasswordParams, UserInfo, VerifyToken,
};
use crate::{err_input, err_server};

/// Get a single user from the DB, searching by username
pub async fn get_user_by_username(username: &str) -> Result<Option<User>, ServerError> {
    let db = &*DB;
    let to_find = username.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::Username.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", username, e));

    if let Ok(user) = user {
        return match user {
            Some(user) => Ok(Option::from(user)),
            None => Ok(None),
        };
    }
    Err(err_server!(
        "Problem querying database for user: cant unwrap ORM"
    ))
}

/// Get a single user from the DB, searching by username
pub async fn get_user_by_email(email: &str) -> Result<Option<User>, ServerError> {
    let db = &*DB;
    let to_find = email.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::Email.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", email, e));

    if let Ok(user) = user {
        return match user {
            Some(user) => Ok(Option::from(user)),
            None => Ok(None),
        };
    }
    Err(err_server!(
        "Problem querying database for user: can't unwrap ORM"
    ))
}

/// Get a user security settings
pub async fn get_user_settings_by_id(user_id: &str) -> Result<SecuritySettings, ServerError> {
    let db = &*DB;
    let setting_result = entity::prelude::UserSecuritySettings::find()
        .filter(user_security_settings::Column::UserId.eq(user_id))
        .one(db)
        .await;

    match setting_result {
        Ok(Some(setting)) => Ok(setting),
        Ok(None) => Err(err_server!(
            "Problem querying database for user settings: can't unwrap ORM"
        )),
        Err(e) => Err(err_server!(
            "Problem querying database for user {}: {}",
            user_id,
            e
        )),
    }
}

/// Get a single user from the DB, searching by username
pub async fn get_user_by_id(id: &str) -> Result<Option<User>, ServerError> {
    let db = &*DB;
    let to_find = id.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::UserId.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", id, e));

    if let Ok(user) = user {
        return match user {
            Some(user) => Ok(Option::from(user)),
            None => Ok(None),
        };
    }
    Err(err_server!(
        "Problem querying database for user: can't unwrap ORM"
    ))
}

pub async fn create_user_and_try_save(
    user_id: &String,
    params: &NewUserParams,
    req: &HttpRequest,
) -> Result<User, ServiceError> {
    let db = &*DB;
    let hash = generate_password_hash(&params.password).map_err(|s| s.general(&req))?;

    let user = user::ActiveModel {
        user_id: Set(user_id.to_string()),
        email: Set(params.email.to_string()),
        username: Set(params.username.to_string()),
        pass_hash: Set(hash.to_string()),
        created_at: Set(Utc::now().naive_utc()),
        updated_at: Set(Utc::now().naive_utc()),
        ..Default::default()
    };
    let user = user.insert(db).await?;
    let settings = user_security_settings::ActiveModel {
        user_id: Set(user_id.to_string()),
        ..Default::default()
    };
    settings.insert(db).await?;
    Ok(user)
}

pub async fn try_send_restore_email(
    req: &HttpRequest,
    params: ForgotPasswordParams,
) -> Result<(), ServiceError> {
    if let Err(e) = validate_username_rules(&params.username) {
        return Err(e.bad_request(&req));
    }
    // Check the password is valid
    if let Err(e) = validate_email_rules(&params.email) {
        return Err(e.bad_request(&req));
    }

    match get_user_by_username(&params.username)
        .await
        .map_err(|s| s.general(&req))?
    {
        Some(user) => {
            if user.email == params.email {
                send_password_reset_email(&user.user_id, &user.email)
                    .await
                    .map_err(|s| ServiceError::general(&req, s.message, false))?;
            }
        }
        None => {}
    };
    Ok(())
}

pub async fn try_reset_password(
    req: &HttpRequest,
    params: ResetPasswordParams,
) -> Result<(), ServiceError> {
    let user = verify_password_reset_token(&params.token)
        .await
        .map_err(|s| s.general(req))?;

    // Check the new password is valid
    if let Err(e) = validate_password_rules(&params.password, &params.password_confirm) {
        return Err(e.bad_request(&req));
    }

    // check user matches the one from the token
    if user.user_id != params.user_id {
        return Err(ServiceError::bad_request(
            &req,
            "User/token mismatch.",
            true,
        ));
    }

    if let Some(user) = get_user_by_id(&params.user_id)
        .await
        .map_err(|s| s.general(&req))?
    {
        let hash = generate_password_hash(&params.password).map_err(|s| s.general(&req))?;

        let db = &*DB;
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

pub async fn add_password_reset_token(
    user_id: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), ServerError> {
    let hashed_token = hash_token(token);
    let db = &*DB;
    if let Some(user) = user_restore_password::Entity::find()
        .filter(user_restore_password::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?
    {
        let mut active: user_restore_password::ActiveModel = user.into();
        active.otp_hash = Set(hashed_token.to_string());
        active.expiry = Set(expiry.naive_utc());
        active
            .update(db)
            .await
            .map_err(|e| err_server!("Problem updating restore token {}:{}", user_id, e))?;
    } else {
        let new_restore = user_restore_password::ActiveModel {
            user_id: Set(user_id.to_string()),
            otp_hash: Set(hashed_token.to_string()),
            expiry: Set(expiry.naive_utc()),
            ..Default::default()
        };
        new_restore
            .insert(db)
            .await
            .map_err(|e| err_server!("Problem adding restore token {}:{}", user_id, e))?;
    }

    Ok(())
}

async fn verify_password_reset_token(token: &str) -> Result<UserInfo, ServerError> {
    let db = &*DB;
    let hashed_token = hash_token(token);
    let user = user_restore_password::Entity::find()
        .filter(user_restore_password::Column::OtpHash.eq(hashed_token))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding password reset token {}: {}", token, e))?
        .ok_or(err_input!("Token not found."))?;

    let user_id = user.user_id.clone();
    let user_expiry = user.expiry;

    user.delete(db)
        .await
        .map_err(|e| err_server!("Problem delete password reset token {}: {}", token, e))?;

    let now = Utc::now().naive_utc();

    return if user_expiry > now {
        Ok(UserInfo { user_id })
    } else {
        Err(ServerError {
            code: ErrorCode::ServerError,
            message: "Token to restore password not found or expiry".to_string(),
            show_message: false,
        })
    };
}

/// Add an email token to the DB
pub async fn add_email_token(
    user_id: &str,
    email: &str,
    token: &str,
    expiry: DateTime<Utc>,
    user_exists: bool,
) -> Result<(), ServerError> {
    let db = &*DB;
    // Uniqueness is taken care of by an index in the DB
    if !user_exists {
        let confirmation = user_confirmation::ActiveModel {
            user_id: Set(user_id.to_string()),
            email: Set(email.to_string()),
            otp_hash: Set(token.to_string()),
            expiry: Set(expiry.naive_utc()),
            ..Default::default()
        };

        confirmation
            .insert(db)
            .await
            .map_err(|e| err_server!("Problem adding email token {}:{}", user_id, e))?;
    } else {
        if let Some(user) = user_confirmation::Entity::find()
            .filter(user_confirmation::Column::UserId.contains(user_id))
            .one(db)
            .await
            .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?
        {
            let mut active: user_confirmation::ActiveModel = user.into();
            active.email = Set(email.to_string());
            active.otp_hash = Set(token.to_string());
            active.expiry = Set(expiry.naive_utc());
            active
                .update(db)
                .await
                .map_err(|e| err_server!("Problem updating active_user {}:{}", user_id, e))?;
        }
    }
    Ok(())
}

pub async fn find_email_verify_token(email: &str) -> Result<VerifyToken, ServerError> {
    let db = &*DB;
    let confirmation = user_confirmation::Entity::find()
        .filter(user_confirmation::Column::Email.contains(email))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding email and token {}:{}", email, e))?;
    match confirmation {
        None => Err(err_server!("Problem finding email and token {}", email)),
        Some(model) => {
            let token = VerifyToken {
                expiry: model.expiry.clone(),
                user_id: model.user_id.clone(),
                otp_hash: model.otp_hash.clone(),
            };
            model
                .delete(db)
                .await
                .map_err(|e| err_server!("Problem delete token with email: {}:{}", email, e))?;
            Ok(token)
        }
    }
}

pub async fn verify_email_by(user_id: &str) -> Result<(), ServerError> {
    let db = &*DB;
    let user = user::Entity::find()
        .filter(user::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?;

    if user.is_none() {
        return Err(err_server!("Problem finding user id {}", user_id));
    }

    let user = user.unwrap();
    if user.email_validated {
        return Ok(());
    }

    let mut item_active_model: user::ActiveModel = user.into();
    item_active_model.email_validated = Set(true);

    item_active_model
        .update(db)
        .await
        .map_err(|e| err_server!("Problem updating user {}:{}", user_id, e))?;
    Ok(())
}

pub async fn block_user_until(user_id: &str, expiry: DateTime<Utc>) -> Result<(), ServerError> {
    if let Some(user) = get_user_by_id(user_id)
        .await
        .map_err(|e| err_server!("Problem finding user {}:{}", user_id, e))?
    {
        let db = &*DB;
        let mut active: user::ActiveModel = user.into();
        active.login_blocked_until = Set(Some(expiry.naive_utc()));
        active
            .update(db)
            .await
            .map_err(|e| err_server!("Problem updating user {}:{}", user_id, e))?;
    }
    Ok(())
}

pub async fn set_attempt_count(
    attempt_count: i32,
    user_id: &str,
    mut new_user: user_otp_token::ActiveModel,
) -> Result<(), ServerError> {
    let db = &*DB;
    new_user.attempt_count = Set(attempt_count);
    new_user
        .update(db)
        .await
        .map_err(|e| err_server!("Problem updating OTP token attempt count {}:{}", user_id, e))?;
    Ok(())
}
