use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmUserAuthenticationRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserAuthenticationRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserAuthenticationDomainRepository for SeaOrmUserAuthenticationRepository {
    async fn get_user_by_email(
        &self,
        query: FindUserByEmailDTO,
    ) -> Result<UserAuthentication, DomainError> {
        todo!()
    }

    async fn get_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserAuthentication, DomainError> {
        todo!()
    }

    async fn save_user_session(&self, session: &UserSession) -> Result<(), DomainError> {
        todo!()
    }

    async fn get_user_sessions(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<(Vec<UserSession>), DomainError> {
        todo!()
    }

    async fn update_user_login_attempts(
        &self,
        user: FindUserByIdDTO,
        count: i32,
    ) -> Result<(), DomainError> {
        todo!()
    }

    async fn block_user_until(
        &self,
        user: &FindUserByIdDTO,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError> {
        todo!()
    }

    async fn prepare_user_for_2fa(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        email_token_hash: Option<String>,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError> {
        todo!()
    }

    async fn set_email_otp_verified(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        todo!()
    }

    async fn set_app_otp_verified(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        todo!()
    }

    async fn reset_2fa_flow_and_login_attempts(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<(), DomainError> {
        todo!()
    }
}
