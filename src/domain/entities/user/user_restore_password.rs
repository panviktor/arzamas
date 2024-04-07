use chrono::{DateTime, Utc};

pub struct UserRestorePassword {
    pub user_id: String,
    pub otp_hash: Option<String>,
    pub expiry: DateTime<Utc>,
}
