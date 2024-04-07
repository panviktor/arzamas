use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_otp_token::UserOtpToken;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::services::user::{CredentialServiceError, ValidationServiceError};
use sea_orm::prelude::DateTime;

#[derive(Debug, Clone)]
pub enum AuthenticationOutcome {
    RequireEmailVerification,
    RequireAuthenticatorApp,
    RequireEmailAndAuthenticatorApp,
    AuthenticatedWithPreferences {
        email: Email,
        email_notifications_enabled: bool,
    },
    AuthenticationFailed {
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    },
}
#[derive(Debug, Clone)]
pub enum VerificationMethod {
    EmailOTP,
    AuthenticatorApp,
}
#[derive(Debug, Clone)]
pub struct VerificationInfo {
    pub method: VerificationMethod,
    pub code: Option<String>,
    pub answers: Option<Vec<String>>,
}

pub struct UserAuthentication {
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub pass_hash: String,
    pub email_validated: bool,
    pub security_setting: UserSecuritySettings,
    pub otp: UserOtpToken,
    pub login_blocked_until: Option<DateTime>,
}

pub enum UserAuthenticationError {
    UserIdentifier(ValidationServiceError),
    CredentialError(CredentialServiceError),
}
