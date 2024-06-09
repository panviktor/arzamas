use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use chrono::{DateTime, Utc};

pub struct RecoveryPasswdRequestDTO {
    pub identifier: String,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
}

pub struct RecoveryPasswdResponse {
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub token: EmailToken,
    pub expiry: DateTime<Utc>,
}

pub enum UserRestorePasswdOutcome {
    ValidToken {
        user_id: String,
        email: Email,
        message: String,
        close_sessions_on_change_password: bool,
    },
    InvalidToken {
        user_id: String,
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    },
}
