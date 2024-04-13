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
        user_id: String,
        session_id: String,
        session_name: String,
        login_timestamp: DateTime<Utc>,
        ip_address: String,
        user_agent: String,
        expiry: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            session_id,
            session_name,
            login_timestamp,
            ip_address,
            user_agent,
            expiry,
        }
    }
}
