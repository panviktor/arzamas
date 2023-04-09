use chrono::NaiveDateTime;
use serde_derive::{Deserialize, Serialize};

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct NewUserParams {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct VerifyEmailParams {
    pub email: String,
    pub email_token: String,
}

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct LoginParams {
    pub identifier: String,
    pub password: String,
    pub persist: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub enum LoginResponse {
    OTPResponse { message: String, apps_code: bool },
    TokenResponse { token: String, token_type: String },
}

#[derive(Serialize, Deserialize)]
pub struct OTPCode {
    pub user_id: String,
    pub email_code: Option<String>,
    pub app_code: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: String,
}

/// Form params for the forgot password form
#[derive(Serialize, Deserialize)]
pub struct ForgotPasswordParams {
    pub(crate) username: String,
    pub(crate) email: String,
}

/// Parameters for the reset password form
#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub struct UserToken {
    // issued at
    pub iat: i64,
    // expiration
    pub exp: i64,
    // data
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
