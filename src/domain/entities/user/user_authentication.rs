use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_otp_token::UserOtpToken;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub enum AuthenticationOutcome {
    RequireEmailVerification {
        user_id: String,
        email: Email,
        token: EmailToken,
        email_notifications_enabled: bool,
    },
    RequireAuthenticatorApp {
        user_id: String,
        email: Email,
        email_notifications_enabled: bool,
    },
    RequireEmailAndAuthenticatorApp {
        user_id: String,
        email: Email,
        token: EmailToken,
        email_notifications_enabled: bool,
    },
    AuthenticatedWithPreferences {
        session: UserSession,
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    },
    AuthenticationFailed {
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    },
    AccountTemporarilyLocked {
        until: DateTime<Utc>,
        message: String,
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
    pub sessions: Vec<UserSession>,
    pub attempt_count: i32,
    pub login_blocked_until: Option<DateTime<Utc>>,
}
