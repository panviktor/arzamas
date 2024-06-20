use crate::domain::entities::shared::{Email, EmailToken};
use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct UserSecuritySettings {
    pub user_id: String,
    pub two_factor_email: bool,
    pub two_factor_authenticator_app: bool,
    pub totp_secret: Option<String>,
    pub email_on_success_enabled_at: bool,
    pub email_on_failure_enabled_at: bool,
    pub close_sessions_on_change_password: bool,
}

#[derive(Debug)]
pub struct UserChangeEmail {
    pub new_email: Email,
    pub old_email: Email,
    pub email_validation_token: EmailToken,
}

pub struct UserChangeEmailConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
    pub new_email: Email,
}

#[derive(Debug)]
pub struct ConfirmEmail2FA {
    pub email: Email,
    pub token: EmailToken,
}

impl ConfirmEmail2FA {
    pub fn new(email: Email, token: EmailToken) -> Self {
        Self { email, token }
    }
}
#[derive(Debug)]
pub struct User2FAEmailConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
    pub user_email: Email,
}
