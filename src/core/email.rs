use entity::user_confirmation;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait};
use sea_orm::ActiveValue::Set;
use crate::core::db::DB;
use crate::err_server;
use crate::models::{ServerError};
use crate::modules::auth::hash_token;

/// Add an email token to the DB
pub async fn add_email_token(
    user_id: &str,
    email: &str,
    token: &str,
    expiry: DateTime<Utc>,
) -> Result<(), ServerError> {
    let db = &*DB;
    let hashed_token = hash_token(token);
    // Uniqueness is taken care of by an index in the DB
    let user = user_confirmation::ActiveModel {
        user_id: Set(user_id.to_string()),
        email: Set(email.to_string()),
        otp_hash: Set(hashed_token.to_string()),
        expiry: Set( expiry.naive_utc() ),
        ..Default::default()
    };

    let result = user.insert(db)
        .await
        .map_err(|e| err_server!("Problem adding email token {}:{}", user_id, e))?;
    Ok(())
}

