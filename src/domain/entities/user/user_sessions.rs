use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct UserSession {
    pub user_id: String,
    pub session_id: String,
    pub session_name: String,
    pub login_timestamp: DateTime<Utc>,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
    pub expiry: DateTime<Utc>,
    pub valid: bool,
}

impl UserSession {
    pub fn new(
        user_id: &str,
        session_id: &str,
        session_name: &str,
        login_timestamp: DateTime<Utc>,
        user_agent: &UserAgent,
        ip_address: &IPAddress,
        expiry: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            session_name: session_name.to_string(),
            login_timestamp,
            ip_address: ip_address.clone(),
            user_agent: user_agent.clone(),
            expiry,
            valid: true,
        }
    }
}
