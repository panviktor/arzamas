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
    OTPResponse { otp: String },
    TokenResponse { token: String, token_type: String}
}

#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub token_type: String
}

#[derive(Serialize, Deserialize)]
pub struct OTPResponse {
    pub otp: String,
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