use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::user::user_sessions::UserSession;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LoginUserRequest {
    pub identifier: String,
    pub password: String,
    pub password_confirm: String,
    pub user_agent: String,
    pub ip_address: String,
    pub persistent: bool,
}

impl LoginUserRequest {
    pub fn new(
        identifier: &str,
        password: &str,
        password_confirm: &str,
        user_agent: &str,
        ip_address: &str,
        persistent: bool,
    ) -> Self {
        Self {
            identifier: identifier.to_string(),
            password: password.to_string(),
            password_confirm: password_confirm.to_string(),
            user_agent: user_agent.to_string(),
            ip_address: ip_address.to_string(),
            persistent,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct OTPCodeRequest {
    pub user_id: String,
    pub email_code: Option<String>,
    pub app_code: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UserToken {
    pub user_id: String,
    pub session_id: String,
    pub session_name: String,
    pub login_timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub expiry: DateTime<Utc>,
}

impl From<UserSession> for UserToken {
    fn from(session: UserSession) -> Self {
        UserToken {
            user_id: session.user_id,
            session_id: session.session_id,
            session_name: session.session_name,
            login_timestamp: session.login_timestamp,
            user_agent: session.user_agent.into_inner(),
            ip_address: session.ip_address.into_inner(),
            expiry: session.expiry,
        }
    }
}
