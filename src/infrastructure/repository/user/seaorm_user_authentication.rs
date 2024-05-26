use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::user;
use entity::user_otp_token;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::ops::Deref;
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
        let user_model = entity::user::Entity::find()
            .filter(user::Column::Email.eq(query.email.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found".to_string(),
                ))
            })?;
        self.fetch_user_details(user_model).await
    }

    async fn get_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserAuthentication, DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::Username.eq(query.username.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found".to_string(),
                ))
            })?;
        self.fetch_user_details(user_model).await
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
        let user_otp_token = entity::user_otp_token::Entity::find()
            .filter(user::Column::Username.eq(user.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Otp token not found".to_string(),
                ))
            })?;

        let mut active: user_otp_token::ActiveModel = user_otp_token.into();
        active.attempt_count = Set(count);
        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn block_user_until(
        &self,
        user: &FindUserByIdDTO,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError> {
        let user = entity::user::Entity::find()
            .filter(user::Column::Username.eq(user.user_id.clone()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found".to_string(),
                ))
            })?;

        let mut active: user::ActiveModel = user.into();
        active.login_blocked_until = Set(expiry.map(|dt| dt.naive_utc()));

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
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

impl SeaOrmUserAuthenticationRepository {
    // Private helper method, not exposed outside this implementation
    async fn fetch_user_details(
        &self,
        user: user::Model,
    ) -> Result<UserAuthentication, DomainError> {
        let otp_token_future = entity::user_otp_token::Entity::find()
            .filter(entity::user_otp_token::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db);

        let security_settings_future = entity::user_security_settings::Entity::find()
            .filter(entity::user_security_settings::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db);

        let sessions_future = entity::user_session::Entity::find()
            .filter(entity::user_session::Column::UserId.eq(user.user_id.clone()))
            .all(&*self.db);

        let (otp_token_model, user_security_settings, user_sessions) =
            tokio::try_join!(otp_token_future, security_settings_future, sessions_future)?;

        let login_blocked_until = user
            .login_blocked_until
            .map(|naive_dt| Utc.from_utc_datetime(&naive_dt));

        let security_setting = user_security_settings
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Security settings not found".to_string(),
                ))
            })?
            .into();

        let otp_token = otp_token_model
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "OTP token not found".to_string(),
                ))
            })?
            .try_into()?;

        let sessions: Vec<UserSession> = user_sessions.into_iter().map(UserSession::from).collect();

        Ok(UserAuthentication {
            user_id: user.user_id,
            email: Email::new(&user.email),
            username: Username::new(&user.username),
            pass_hash: user.pass_hash,
            email_validated: user.email_validated,
            security_setting,
            otp: otp_token,
            sessions,
            login_blocked_until,
        })
    }
}
