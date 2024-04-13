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
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            expiry: session.expiry,
        }
    }
}
