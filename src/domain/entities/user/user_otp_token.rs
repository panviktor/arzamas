use chrono::{DateTime, Utc};

pub struct UserOtpToken {
    pub user_id: String,
    pub otp_email_hash: Option<String>,
    pub otp_app_hash: Option<String>,
    pub otp_app_mnemonic: Option<String>,
    pub expiry: DateTime<Utc>,
    pub attempt_count: i32,
    pub code: Option<String>,
}
