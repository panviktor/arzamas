use chrono::{DateTime, Utc};

pub struct UserEmailConfirmation {
    pub otp_hash: String,
    pub expiry: DateTime<Utc>,
}
