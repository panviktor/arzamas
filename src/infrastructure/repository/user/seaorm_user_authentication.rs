use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_otp_token::UserOtpToken;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, TransactionTrait};
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
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        let user_model = entity::user::Entity::find()
            .filter(entity::user::Column::Email.eq(query.email.value()))
            .one(&txn)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;

        if let Some(user) = user_model {
            let login_blocked_until = user
                .login_blocked_until
                .map(|naive_dt| Utc.from_utc_datetime(&naive_dt));

            let otp_token_model = entity::user_otp_token::Entity::find()
                .filter(entity::user_otp_token::Column::UserId.eq(user.user_id.clone()))
                .one(&txn)
                .await
                .map_err(|e| {
                    DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
                })?;

            let user_security_settings = entity::user_security_settings::Entity::find()
                .filter(entity::user_security_settings::Column::UserId.eq(user.user_id.clone()))
                .one(&txn)
                .await
                .map_err(|e| {
                    DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
                })?;

            if let (Some(otp_token), Some(security_settings)) =
                (otp_token_model, user_security_settings)
            {
                let security_setting: UserSecuritySettings = security_settings.into();
                let otp_token: UserOtpToken = otp_token.try_into()?;

                return Ok(UserAuthentication {
                    user_id: user.user_id,
                    email: Email::new(&user.email),
                    username: Username::new(&user.username),
                    pass_hash: user.pass_hash,
                    email_validated: user.email_validated,
                    security_setting,
                    otp: otp_token,
                    sessions: Vec::new(),
                    login_blocked_until,
                });
            }
        }

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
        persistent: bool,
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
