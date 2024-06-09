use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmUserRecoveryRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserRecoveryRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserRecoveryPasswdDomainRepository for SeaOrmUserRecoveryRepository {
    async fn get_user_by_email(
        &self,
        query: FindUserByEmailDTO,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        todo!()
    }

    async fn get_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        todo!()
    }

    async fn update_user_restore_attempts(
        &self,
        user: FindUserByIdDTO,
        count: i32,
    ) -> Result<(), DomainError> {
        todo!()
    }

    async fn block_user_restore_until(
        &self,
        user: &FindUserByIdDTO,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError> {
        todo!()
    }

    async fn prepare_user_restore_passwd(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        email_token_hash: String,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError> {
        todo!()
    }
}
