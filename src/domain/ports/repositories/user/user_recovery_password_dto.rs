use crate::domain::entities::shared::value_objects::{IPAddress, OtpToken, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use chrono::{DateTime, Utc};

pub struct RecoveryPasswdRequestDTO {
    pub identifier: String,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
}

impl RecoveryPasswdRequestDTO {
    pub fn new(identifier: String, user_agent: UserAgent, ip_address: IPAddress) -> Self {
        Self {
            identifier,
            user_agent,
            ip_address,
        }
    }
}

pub struct RecoveryPasswdResponse {
    pub email: Email,
    pub username: Username,
    pub token: OtpToken,
    pub expiry: DateTime<Utc>,
}

pub struct UserCompleteRecoveryRequestDTO {
    pub token: OtpToken,
    pub new_password: String,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
}

impl UserCompleteRecoveryRequestDTO {
    pub fn new(
        token: OtpToken,
        new_password: String,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Self {
        Self {
            token,
            new_password,
            user_agent,
            ip_address,
        }
    }
}

pub enum UserRecoveryPasswdOutcome {
    ValidToken {
        user_id: String,
        email: Email,
        message: String,
        close_sessions_on_change_password: bool,
    },
    InvalidToken {
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    },
}
