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
    PendingVerification {
        user_id: String,
        message: String,
    },
}

#[derive(Debug)]
pub struct UserAuthentication {
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub pass_hash: String,
    pub email_validated: bool,
    pub security_setting: UserSecuritySettings,
    pub otp: UserOtpToken,
    pub sessions: Vec<UserSession>,
    pub login_blocked_until: Option<DateTime<Utc>>,
}
