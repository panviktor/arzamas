use crate::domain::entities::shared::value_objects::{OtpCode, UserId};
use crate::domain::entities::shared::{Email, IPAddress, OtpToken, UserAgent, Username};
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
    pub user_id: UserId,
    pub username: Username,
    pub email: Email,
    pub user_credentials: UserCredentials,
    pub security_setting: UserSecuritySettings,
    pub auth_data: UserAuthenticationData,
    pub sessions: Vec<UserSession>,
}

#[derive(Debug)]
pub struct UserCredentials {
    pub pass_hash: String,
    pub email_validated: bool,
    pub totp_secret: Option<String>,
}

#[derive(Debug)]
pub struct UserAuthenticationData {
    pub otp_email_code_hash: Option<OtpCode>,

    pub otp_email_currently_valid: bool,

    pub otp_app_currently_valid: bool,

    pub expiry: Option<DateTime<Utc>>,

    pub attempt_count: i64,

    pub user_agent: Option<UserAgent>,

    pub ip_address: Option<IPAddress>,

    pub long_session: bool,

    pub login_blocked_until: Option<DateTime<Utc>>,
}
