use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use chrono::{DateTime, Utc};

pub struct UserSessionResponse {
    pub session_id: String,
    pub session_name: String,
    pub login_timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub expiry: DateTime<Utc>,
    pub valid: bool,
}

impl From<UserSession> for UserSessionResponse {
    fn from(session: UserSession) -> Self {
        UserSessionResponse {
            session_id: session.session_id,
            session_name: session.session_name,
            login_timestamp: session.login_timestamp,
            ip_address: session.ip_address.into_inner(),
            user_agent: session.user_agent.into_inner(),
            expiry: session.expiry,
            valid: session.valid,
        }
    }
}

pub struct SecuritySettingsResponse {
    pub two_factor_email: bool,
    pub two_factor_authenticator_app: bool,
    pub email_on_success: bool,
    pub email_on_failure: bool,
    pub close_sessions_on_change_password: bool,
}

impl From<UserSecuritySettings> for SecuritySettingsResponse {
    fn from(settings: UserSecuritySettings) -> Self {
        SecuritySettingsResponse {
            two_factor_email: settings.two_factor_email,
            two_factor_authenticator_app: settings.two_factor_authenticator_app,
            email_on_success: settings.email_on_success_enabled_at,
            email_on_failure: settings.email_on_failure_enabled_at,
            close_sessions_on_change_password: settings.close_sessions_on_change_password,
        }
    }
}
