use crate::domain::entities::shared::value_objects::OtpCode;
use crate::domain::entities::shared::{Email, OtpToken, Username};
use crate::domain::entities::user::user_otp_token::UserAuthToken;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub enum AuthenticationOutcome {
    /// The first step is ok, but user needs email verification.
    RequireEmailVerification {
        otp_token: OtpToken,
        otp_code: OtpCode,
        email: Email,
    },
    /// The first step is ok, but user needs 2FA Authenticator verification
    RequireAuthenticatorApp {
        otp_token: OtpToken,
        otp_code: OtpCode,
        email: Email,
        email_notifications_enabled: bool,
    },
    /// The first step is ok, but user needs both email and 2FA Authenticator verification
    RequireEmailAndAuthenticatorApp {
        otp_token: OtpToken,
        otp_code: OtpCode,
        email: Email,
    },
    /// Successfully authenticated and session stored in Redis
    AuthenticatedWithPreferences {
        session: UserSession,
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    },
    /// Login failed (password/2FA)
    AuthenticationFailed {
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    },
    /// User has logged in with user and password, awaiting 2FA authentication
    PendingVerification { message: String },
    /// User hasn't activated email token after registration
    UserEmailConfirmation { email: Email, token: OtpToken },
}

#[derive(Debug)]
pub struct UserAuthentication {
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub pass_hash: String,
    pub email_validated: bool,
    pub security_setting: UserSecuritySettings,
    pub auth_token: UserAuthToken,
    pub sessions: Vec<UserSession>,
    pub login_blocked_until: Option<DateTime<Utc>>,
}
