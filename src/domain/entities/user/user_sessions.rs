use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct UserSession {
    pub user_id: String,
    pub session_id: String,
    pub session_name: String,
    pub login_timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub expiry: DateTime<Utc>,
}

impl UserSession {
    pub fn new(
        user_id: &str,
        session_id: &str,
        session_name: &str,
        login_timestamp: DateTime<Utc>,
        ip_address: &str,
        user_agent: &str,
        expiry: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            session_name: session_name.to_string(),
            login_timestamp,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            expiry,
        }
    }
}
