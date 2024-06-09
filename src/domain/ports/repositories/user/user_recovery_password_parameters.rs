use crate::domain::entities::email::EmailMessage;
use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
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
    pub user_id: String,
    pub email: Email,
    pub username: Username,
    pub token: EmailToken,
    pub expiry: DateTime<Utc>,
}

pub struct UserCompleteRecoveryRequestDTO {
    pub token: String,
    pub new_password: String,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
}

impl UserCompleteRecoveryRequestDTO {
    pub fn new(
        token: String,
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
        message: EmailMessage,
        close_sessions_on_change_password: bool,
    },
    InvalidToken {
        user_id: String,
        email: Email,
        message: EmailMessage,
        email_notifications_enabled: bool,
    },
}
