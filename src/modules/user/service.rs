use actix_web::HttpRequest;
use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::Set;
use serde_derive::{Deserialize, Serialize};
use entity::user;

use crate::core::db::DB;
use crate::models::ServiceError;
use crate::modules::auth::credentials::{
    credential_validator,
    generate_password_hash,
    validate_password_rules
};
use crate::modules::auth::service::get_user_by_id;

/// Form parameters for changing a user's email.
#[derive(Serialize, Deserialize)]
pub struct ChangeEmailParams {
    current_password: String,
    new_email: String,
    csrf: String,
}

pub async fn try_change_email(
    req: &HttpRequest,
    user: &str,
    params: ChangePasswordParams
) -> Result<(), ServiceError> {

    Ok(())
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ChangePasswordParams {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

pub async fn try_change_password(
    req: &HttpRequest,
    user_id: &str,
    params: ChangePasswordParams
) -> Result<(), ServiceError> {
    // Check the password is valid
    if let Err(e) = validate_password_rules(
        &params.new_password,
        &params.new_password_confirm
    ) {
        return Err(ServiceError::bad_request(
            &req,
            format!("{}", e),
            true
        ));
    }
    if let Some(user) = get_user_by_id(user_id)
        .await
        .map_err(|s| s.general(&req))? {

        if !credential_validator(&user, &params.current_password)
            .map_err(|e| e.general(&req))? {
            return Err(ServiceError::bad_request(
                &req,
                "Invalid current password",
                true,
            ));
        }

        let db = &*DB;
        let hash = generate_password_hash(&params.new_password)
            .map_err(|s| s.general(&req))?;
        let mut active: user::ActiveModel = user.into();
        active.pass_hash = Set(hash.to_owned());
        active.update(db).await?;

        /// Add optional invalidate all user session
        /// based on user preferences
    }
    Ok(())
}