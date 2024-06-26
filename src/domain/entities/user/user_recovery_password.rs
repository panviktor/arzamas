use crate::domain::entities::shared::{Email, IPAddress, UserAgent, Username};
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use chrono::{DateTime, Utc};

pub struct UserRecoveryPasswd {
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub user_agent: Option<UserAgent>,
    pub ip_address: Option<IPAddress>,
    pub security_setting: UserSecuritySettings,
    pub expiry: Option<DateTime<Utc>>,
    pub attempt_count: i64,
    pub restore_blocked_until: Option<DateTime<Utc>>,
}

impl UserRecoveryPasswd {
    pub fn new(
        user_id: String,
        email: Email,
        username: Username,
        user_agent: Option<UserAgent>,
        ip_address: Option<IPAddress>,
        security_setting: UserSecuritySettings,
        expiry: Option<DateTime<Utc>>,
        attempt_count: i64,
        restore_blocked_until: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            user_id,
            email,
            username,
            user_agent,
            ip_address,
            security_setting,
            expiry,
            attempt_count,
            restore_blocked_until,
        }
    }
}
