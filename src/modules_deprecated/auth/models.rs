use chrono::NaiveDateTime;
use serde_derive::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, ToSchema)]
pub struct VerifyEmailParams {
    pub email: String,
    pub email_token: String,
}

/// Struct for holding the form parameters with the new user form

#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: String,
}

/// Form params for the forgot password form
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ForgotPasswordParams {
    pub(crate) username: String,
    pub(crate) email: String,
}

/// Parameters for the reset password form
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ResetPasswordParams {
    pub(crate) user_id: String,
    pub(crate) token: String,
    pub(crate) password: String,
    pub(crate) password_confirm: String,
}

pub struct VerifyToken {
    pub expiry: NaiveDateTime,
    pub user_id: String,
    pub otp_hash: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserToken {
    // issued at
    pub iat: i64,
    // expiration
    pub exp: i64,
    // user_id
    pub user_id: String,
    // session
    pub session_id: String,
    // random session name
    pub session_name: String,
    // login ip
    pub login_ip: String,
    // User-Agent
    pub user_agent: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreatedUserDTO {
    pub username: String,
    pub creation_day: NaiveDateTime,
    pub user_email: String,
    pub description: String,
}
