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
    },
    RequireAuthenticatorApp {
        user_id: String,
        email: Email,
        email_notifications_enabled: bool,
    },
    RequireEmailAndAuthenticatorApp {
        user_id: String,
        email: Email,
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
    pub login_blocked_until: DateTime<Utc>,
}

pub struct EmailToken(pub String);
impl EmailToken {
    pub fn new(token: &str) -> Self {
        Self(token.to_string())
    }
    pub fn value(&self) -> &String {
        &self.0
    }
}

impl EmailToken {
    pub fn into_inner(self) -> String {
        self.0
    }
}
