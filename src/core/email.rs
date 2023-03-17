use entity::{
    user,
    user_confirmation,
    user_restore_password
};
use chrono::{DateTime, NaiveDateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter};
use sea_orm::ActiveValue::Set;
use crate::core::db::DB;
use crate::err_server;
use crate::models::{ServerError};

/// Add an email token to the DB
pub async fn add_email_token(
    user_id: &str,
    email: &str,
    token: &str,
    expiry: DateTime<Utc>,
    user_exists: bool
) -> Result<(), ServerError> {
    let db = &*DB;
    // Uniqueness is taken care of by an index in the DB
    if !user_exists {
        let confirmation = user_confirmation::ActiveModel {
            user_id: Set(user_id.to_string()),
            email: Set(email.to_string()),
            otp_hash: Set(token.to_string()),
            expiry: Set( expiry.naive_utc() ),
            ..Default::default()
        };

        confirmation.insert(db)
            .await
            .map_err(|e| err_server!("Problem adding email token {}:{}", user_id, e))?;
    } else {
        if let Some(user) = user_confirmation::Entity::find()
            .filter(user_confirmation::Column::UserId.contains(user_id))
            .one(db)
            .await
            .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))? {

            let mut active: user_confirmation::ActiveModel = user.into();
            active.email = Set(email.to_string());
            active.otp_hash = Set(token.to_string());
            active.expiry = Set( expiry.naive_utc());
            active.update(db)
                .await
                .map_err(|e| err_server!("Problem updating active_user {}:{}", user_id, e))?;
        }
    }
    Ok(())
}

pub struct VerifyToken {
   pub expiry: NaiveDateTime,
   pub user_id: String,
   pub otp_hash: String
}

pub async fn find_email_verify_token(
    email: &str,
) -> Result<VerifyToken, ServerError> {
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
        Some(model) => {
            let token = VerifyToken {
                expiry: model.expiry.clone(),
                user_id: model.user_id.clone(),
                otp_hash: model.otp_hash.clone(),
            };
            model
                .delete(db).await
                .map_err(|e| err_server!("Problem delete token with email: {}:{}", email, e))?;;
            Ok(token)
        }
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
        return Ok(())
    }

    let mut item_active_model: user::ActiveModel = user.into();
    item_active_model.email_validated = Set(true);

    item_active_model
        .update(db)
        .await
        .map_err(|e| err_server!("Problem updating user {}:{}", user_id, e))?;
    Ok(())
}

pub async fn add_password_reset_token(
    user_id: &str,
    token: &str,
    expiry: DateTime<Utc>
) -> Result<(), ServerError> {

    let db = &*DB;
    if let Some(user) = user_restore_password::Entity::find()
        .filter(user_restore_password::Column::UserId.contains(user_id))
        .one(db)
        .await
        .map_err(|e| err_server!("Problem finding user id {}:{}", user_id, e))? {

        let mut active: user_restore_password::ActiveModel = user.into();
        active.otp_hash = Set(token.to_string());
        active.expiry = Set(expiry.naive_utc());
        active.update(db)
            .await
            .map_err(|e| err_server!("Problem updating restore token {}:{}", user_id, e))?;
    } else {
       let new_restore = user_restore_password::ActiveModel {
            user_id: Set(user_id.to_string()),
            otp_hash: Set(token.to_string()),
            expiry: Set(expiry.naive_utc()),
            ..Default::default()
        };
        new_restore.insert(db)
            .await
            .map_err(|e| err_server!("Problem adding restore token {}:{}", user_id, e))?;
    }

    Ok(())
}