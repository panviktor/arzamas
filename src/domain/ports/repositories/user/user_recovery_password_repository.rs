use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserRecoveryPasswdDomainRepository {
    async fn get_user_by_email(
        &self,
        query: FindUserByEmailDTO,
    ) -> Result<UserRecoveryPasswd, DomainError>;

    async fn get_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserRecoveryPasswd, DomainError>;

    async fn update_user_restore_attempts(
        &self,
        user: &FindUserByIdDTO,
        count: i64,
    ) -> Result<(), DomainError>;

    async fn block_user_restore_until(
        &self,
        user: &FindUserByIdDTO,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError>;

    async fn get_recovery_token(
        &self,
        token: EmailToken,
    ) -> Result<UserRecoveryPasswd, DomainError>;

    async fn prepare_user_restore_passwd(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        token: EmailToken,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError>;
}
