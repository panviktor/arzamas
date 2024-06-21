use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::value_objects::{OtpCode, UserId};
use crate::domain::entities::shared::{Email, OtpToken, Username};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::user_authentication;
use entity::{user, user_session};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
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
    async fn get_user_by_email(&self, email: Email) -> Result<UserAuthentication, DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::Email.eq(email.value()))
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
        username: &Username,
    ) -> Result<UserAuthentication, DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::Username.eq(username.value()))
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
        let active_model = session.clone().into_active_model();
        active_model
            .save(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        Ok(())
    }

    async fn update_user_login_attempts(
        &self,
        user: UserId,
        count: i64,
    ) -> Result<(), DomainError> {
        let mut user_otp_token = self.fetch_user_otp_token(&user.user_id).await?;
        user_otp_token.attempt_count = Set(count);
        user_otp_token
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn block_user_until(
        &self,
        user: &UserId,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError> {
        let user = entity::user::Entity::find()
            .filter(user::Column::Username.eq(user.user_id.clone()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User for blocking not found.".to_string(),
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
        user: UserId,
        otp_public_token: OtpToken,
        email_otp_code_hash: Option<OtpCode>,
        code_expiry: DateTime<Utc>,
        user_agent: UserAgent,
        ip_address: IPAddress,
        long_session: bool,
    ) -> Result<(), DomainError> {
        let mut otp = self.fetch_user_otp_token(&user.user_id).await?;

        // user_otp_token.otp_email_currently_valid = Set(false);
        // user_otp_token.otp_app_currently_valid = Set(false);
        // user_otp_token.expiry = Set(Some(expiry.naive_utc()));
        // user_otp_token.otp_email_hash = Set(email_token_hash);
        //
        // user_otp_token.user_agent = Set(Some(user_agent.value().to_string()));
        // user_otp_token.ip_address = Set(Some(ip_address.value().to_string()));
        // user_otp_token.long_session = Set(persistent);

        otp.update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn set_email_otp_verified(&self, user: UserId) -> Result<(), DomainError> {
        let mut user_otp_token = self.fetch_user_otp_token(&user.user_id).await?;
        user_otp_token.otp_email_currently_valid = Set(true);
        user_otp_token
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn set_app_otp_verified(&self, user: UserId) -> Result<(), DomainError> {
        let mut user_otp_token = self.fetch_user_otp_token(&user.user_id).await?;
        user_otp_token.otp_app_currently_valid = Set(true);
        user_otp_token
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn reset_otp_validity(&self, user: UserId) -> Result<(), DomainError> {
        let mut user_otp_token = self.fetch_user_otp_token(&user.user_id).await?;

        user_otp_token.otp_email_currently_valid = Set(false);
        user_otp_token.otp_app_currently_valid = Set(false);
        user_otp_token
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }
}

impl SeaOrmUserAuthenticationRepository {
    // Private helper method, not exposed outside this implementation
    async fn fetch_user_details(
        &self,
        user: user::Model,
    ) -> Result<UserAuthentication, DomainError> {
        let otp_token_future = entity::user_authentication::Entity::find()
            .filter(user_authentication::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db);

        let security_settings_future = entity::user_security_settings::Entity::find()
            .filter(entity::user_security_settings::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db);

        let sessions_future = entity::user_session::Entity::find()
            .filter(user_session::Column::UserId.eq(user.user_id.clone()))
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
            .into();

        let sessions: Vec<UserSession> = user_sessions.into_iter().map(UserSession::from).collect();

        Ok(UserAuthentication {
            user_id: user.user_id,
            email: Email::new(&user.email),
            username: Username::new(&user.username),
            pass_hash: user.pass_hash,
            email_validated: user.email_validated,
            security_setting,
            auth_data: otp_token,
            sessions,
            login_blocked_until,
        })
    }

    async fn fetch_user_otp_token(
        &self,
        user_id: &str,
    ) -> Result<user_authentication::ActiveModel, DomainError> {
        let token_model = entity::user_authentication::Entity::find()
            .filter(user_authentication::Column::UserId.eq(user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))
            .and_then(|opt_model| {
                opt_model.ok_or_else(|| {
                    DomainError::PersistenceError(PersistenceError::Retrieve(
                        "OTP token not found".to_string(),
                    ))
                })
            })?;

        Ok(token_model.into())
    }
}
