use crate::domain::entities::user::user_sessions::UserSession;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
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
