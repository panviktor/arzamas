use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait,
    EntityTrait,
    QueryFilter,
    ColumnTrait,
    NotSet,
    Set
};
use serde_derive::{Deserialize, Serialize};
use entity::user::Model as User;
use entity::user;
use crate::{err_server, };
use crate::core::db::DB;
use crate::models::{ServerError, ServiceError};
use crate::modules::auth::controller::NewUserParams;
use crate::modules::auth::credentials::{
    generate_password_hash,
    validate_email_rules,
    validate_username_rules
};
use crate::modules::auth::email::send_password_reset_email;

/// Get a single user from the DB, searching by username
pub async fn get_user_by_username(username: &str) -> Result<Option<User>, ServerError> {

    let db = &*DB;
    let to_find =  username.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::Username.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", username, e));

    if let Ok(user) = user {
        return match user {
            Some(user) => {
                Ok(Option::from(user))
            }
            None => { Ok(None) }
        }
    }
    Err(err_server!("Problem querying database for user: cant unwrap ORM"))
}

/// Get a single user from the DB, searching by username
pub async fn get_user_by_email(email: &str) -> Result<Option<User>, ServerError> {

    let db = &*DB;
    let to_find =  email.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::Email.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", email, e));

    if let Ok(user) = user {
        return match user {
            Some(user) => {
                Ok(Option::from(user))
            }
            None => { Ok(None) }
        }
    }
    Err(err_server!("Problem querying database for user: can't unwrap ORM"))
}

/// Get a single user from the DB, searching by username
pub async fn get_user_by_id(id: &str) -> Result<Option<User>, ServerError> {

    let db = &*DB;
    let to_find =  id.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::UserId.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", id, e));

    if let Ok(user) = user {
        return match user {
            Some(user) => {
                Ok(Option::from(user))
            }
            None => { Ok(None) }
        }
    }
    Err(err_server!("Problem querying database for user: can't unwrap ORM"))
}

pub async fn create_user_and_try_save(
    user_id: &String,
    params: &NewUserParams,
    req: &HttpRequest
) -> Result<User, ServiceError> {

    let db = &*DB;
    let hash = generate_password_hash(&params.password).map_err(|s| s.general(&req))?;

    let user = user::ActiveModel {
        user_id: Set(user_id.to_string()),
        email: Set(params.email.to_string()),
        username: Set(params.username.to_string()),
        pass_hash: Set(hash.to_string()),
        totp_active: Set(false),
        totp_token: NotSet,
        totp_backups: NotSet,
        created_at: Set( Utc::now().naive_utc()),
        updated_at: Set( Utc::now().naive_utc()),
        ..Default::default()
    };

    let result = user.insert(db).await;
    match result {
        Ok(user) => { Ok(user) }
        Err(err) => {
            Err(ServiceError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: req.path().to_string(),
                message: err.to_string(),
                show_message: false,
            })
        }
    }
}

pub async fn try_send_restore_email(
    req: &HttpRequest,
    params: ForgotPasswordParams
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
    params: ResetPasswordParams
) -> Result<(), ServiceError> {

    Ok(())
}

/// Form params for the forgot password form
#[derive(Serialize, Deserialize)]
pub struct ForgotPasswordParams {
    username: String,
    email: String,
}

/// Parameters for the reset password form
#[derive(Serialize, Deserialize)]
pub struct ResetPasswordParams {
    user_id: String,
    token: String,
    password: String,
    password_confirm: String,
}