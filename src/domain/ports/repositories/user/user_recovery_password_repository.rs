use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserRecoveryPasswdDomainRepository {
    async fn get_user_by_email(&self, query: Email) -> Result<UserRecoveryPasswd, DomainError>;

    async fn get_user_by_username(
        &self,
        query: Username,
    ) -> Result<UserRecoveryPasswd, DomainError>;

    async fn update_user_restore_attempts_and_block(
        &self,
        user: &UserId,
        count: i64,
        block_until: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError>;

    async fn reset_restore_attempts_and_block(&self, user: &UserId) -> Result<(), DomainError>;

    async fn get_recovery_token(
        &self,
        token: &EmailToken,
    ) -> Result<UserRecoveryPasswd, DomainError>;

    async fn prepare_user_restore_passwd(
        &self,
        user: UserId,
        expiry: DateTime<Utc>,
        token: EmailToken,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError>;
}
