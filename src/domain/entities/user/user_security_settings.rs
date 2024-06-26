use crate::domain::entities::shared::{Email, OtpToken};
use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct UserSecuritySettings {
    pub two_factor_email: bool,
    pub two_factor_authenticator_app: bool,
    pub email_on_success_enabled_at: bool,
    pub email_on_failure_enabled_at: bool,
    pub close_sessions_on_change_password: bool,
}

#[derive(Debug)]
pub struct UserChangeEmail {
    pub new_email: Email,
    pub old_email: Email,
    pub email_validation_token: OtpToken,
}

pub struct UserEmailConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
}

pub struct UserChangeEmailConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
    pub new_email: Email,
}

#[derive(Debug)]
pub struct ConfirmEnableEmail2FA {
    pub email: Email,
    pub token: OtpToken,
}

impl ConfirmEnableEmail2FA {
    pub fn new(email: Email, token: OtpToken) -> Self {
        Self { email, token }
    }
}

pub struct User2FAEmailConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
    pub user_email: Email,
}

impl User2FAEmailConfirmation {
    pub fn new(otp_hash: String, expiry: DateTime<Utc>, user_email: Email) -> Self {
        Self {
            otp_hash,
            expiry,
            user_email,
        }
    }
}

pub struct InitiateDeleteUserResponse {
    pub email: Email,
    pub token: OtpToken,
}

pub struct DeleteUserConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ConfirmEnableApp2FA {
    pub email: Email,
    pub token: OtpToken,
    pub secret: String,
    pub totp_uri: String,
}

impl ConfirmEnableApp2FA {
    pub fn new(email: Email, token: OtpToken, secret: String, totp_uri: String) -> Self {
        Self {
            email,
            token,
            secret,
            totp_uri,
        }
    }
}

pub struct ConfirmDisableApp2FA {
    pub email: Email,
    pub token: OtpToken,
}

pub struct User2FAAppConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
    pub secret: String,
}

impl User2FAAppConfirmation {
    pub fn new(otp_hash: String, expiry: DateTime<Utc>, secret: String) -> Self {
        Self {
            otp_hash,
            expiry,
            secret,
        }
    }
}
