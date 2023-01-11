use actix_web::http::StatusCode;
use actix_web::HttpRequest;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, QueryFilter, ColumnTrait, NotSet, Set };
use entity::user::Model as User;
use entity::user;
use crate::{err_server, };
use crate::core::db::DB;
use crate::models::{ServerError, ServiceError};
use crate::modules::auth::controller::NewUserParams;
use crate::modules::auth::credentials::generate_password_hash;

/// Get a single user from the DB, searching by username
pub async fn get_user_by_username(username: &str) -> Result<Option<User>, ServerError> {

    let db = &*DB;
    let to_find =  username.to_string();
    let user = entity::prelude::User::find()
        .filter(user::Column::Username.eq(&*to_find))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem querying database for user {}: {}", username, e));

    match user {
        Ok(user) => {
            match user {
                Some(user) => {
                    Ok(Option::from(user))
                }
                None => {
                    Ok(None)
                }
            }
        }
        Err(_) => {
            Err(err_server!("Problem querying database for user: cant unwrap ORM"))
        }
    }
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

    match user {
        Ok(user) => {
            match user {
                Some(user) => {
                    Ok(Option::from(user))
                }
                None => {
                    Ok(None)
                }
            }
        }
        Err(_) => {
            Err(err_server!("Problem querying database for user: cant unwrap ORM"))
        }
    }
}

pub async fn create_user_and_try_save(
    user_id: &String,
    params: &NewUserParams,
    req: &HttpRequest
) -> Result<User, ServiceError> {

    // insert user
    let db = &*DB;
    // create password hash
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
            let ds = err.to_string();
            Err(ServiceError {
                code: StatusCode::INTERNAL_SERVER_ERROR,
                path: req.path().to_string(),
                message: err.to_string(),
                show_message: false,
            })
        }
    }
}

/// Get a single user from the DB searching by user ID
pub async fn get_user_by_userid(user_id: &str)  {

}