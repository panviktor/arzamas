use entity::{user, user_confirmation};
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, QueryFilter};
use sea_orm::ActiveValue::Set;
use entity::user::Model;
use crate::core::db::DB;
use crate::err_server;
use crate::models::{ServerError};

/// Add an email token to the DB
pub async fn add_email_token(
    user_id: &str,
    email: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), ServerError> {
    let db = &*DB;
    // Uniqueness is taken care of by an index in the DB
    let confirmation = user_confirmation::ActiveModel {
        user_id: Set(user_id.to_string()),
        email: Set(email.to_string()),
        otp_hash: Set(token.to_string()),
        expiry: Set( expiry.naive_utc() ),
        ..Default::default()
    };

    let result = confirmation.insert(db)
        .await
        .map_err(|e| err_server!("Problem adding email token {}:{}", user_id, e))?;
    Ok(())
}

pub async fn find_email_verify_token(
    email: &str,
) -> Result<(user_confirmation::Model), ServerError> {
    let db = &*DB;
    let confirmation = user_confirmation::Entity::find()
        .filter(user_confirmation::Column::Email.contains(email))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding email and token {}:{}", email, e))?;
    match confirmation {
        None => {
            Err(err_server!("Problem finding email and token {}", email))
        }
        Some(model) => { Ok(model) }
    }
}

pub async fn verify_email_by(
    user_id: &str,
) -> Result<(), ServerError> {
    let db = &*DB;
    let user = user::Entity::find()
        .filter(user::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))?;

    if user.is_none() {
        return Err(err_server!("Problem finding user id {}", user_id))
    }

    let user = user.unwrap();
    if user.email_validated {
        println!("Double validated");
        return Ok(())
    }

    let mut item_active_model: user::ActiveModel = user.into();
    item_active_model.email_validated = Set(true);
    let result = item_active_model
        .update(db)
        .await
        .map_err(|e| err_server!("Problem updating user {}:{}", user_id, e))?;

    Ok(())

}