use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use chrono::{DateTime, Utc};

pub struct UserRecoveryPasswd {
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub user_agent: Option<UserAgent>,
    pub ip_address: Option<IPAddress>,
    pub security_setting: UserSecuritySettings,
    pub pass_hash: Option<String>,
    pub restore_blocked_until: Option<DateTime<Utc>>,
}
