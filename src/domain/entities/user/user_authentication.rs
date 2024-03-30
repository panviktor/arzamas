use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAuthentication {
    user_id: String,
    email: String,
    username: String,
    email_validated: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    login_blocked_until: Option<DateTime<Utc>>,
}
