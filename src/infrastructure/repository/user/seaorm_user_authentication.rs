use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::value_objects::{OtpCode, UserId};
use crate::domain::entities::shared::{Email, OtpToken, Username};
use crate::domain::entities::user::user_authentication::{
    UserAuthentication, UserAuthenticationData,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::user_authentication;
use entity::{user, user_session};
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, JoinType, QueryFilter,
    QuerySelect, RelationTrait,
};
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
        let mut active = self.fetch_user_otp_token(&user.user_id).await?;
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
        email_otp_code_hash: Option<String>,
        code_expiry: DateTime<Utc>,
        user_agent: UserAgent,
        ip_address: IPAddress,
        long_session: bool,
    ) -> Result<(), DomainError> {
        let mut otp = self.fetch_user_otp_token(&user.user_id).await?;

        otp.otp_email_currently_valid = Set(false);
        otp.otp_app_currently_valid = Set(false);

        otp.expiry = Set(Some(code_expiry.naive_utc()));
        otp.otp_public_token = Set(Some(otp_public_token.into_inner()));
        otp.otp_email_code_hash = Set(email_otp_code_hash);

        otp.user_agent = Set(Some(user_agent.value().to_string()));
        otp.ip_address = Set(Some(ip_address.value().to_string()));
        otp.long_session = Set(long_session);

        otp.update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn fetch_user_auth_by_token(
        &self,
        otp_public_token: OtpToken,
    ) -> Result<UserAuthentication, DomainError> {
        // Fetch the user authentication data by the public token
        let auth = entity::user_authentication::Entity::find()
            .filter(user_authentication::Column::OtpPublicToken.eq(otp_public_token.into_inner()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User authentication data not found".to_string(),
                ))
            })?;

        self.fetch_user_auth(auth).await
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
        let mut active = self.fetch_user_otp_token(&user.user_id).await?;

        active.otp_email_currently_valid = Set(false);
        active.otp_app_currently_valid = Set(false);

        active.expiry = Set(None);
        active.otp_public_token = Set(None);
        active.otp_email_code_hash = Set(None);

        active.user_agent = Set(None);
        active.ip_address = Set(None);

        active
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

        let security_setting = user_security_settings
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Security settings not found".to_string(),
                ))
            })?
            .into();

        let email = Email::new(&user.email);
        let otp_token = otp_token_model.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "OTP token not found".to_string(),
            ))
        })?;

        let sessions: Vec<UserSession> = user_sessions.into_iter().map(UserSession::from).collect();

        Ok(UserAuthentication {
            user_id: user.user_id,
            username: Username::new(&user.username),
            email: Email::new(&user.email),
            pass_hash: user.pass_hash,
            email_validated: user.email_validated,
            security_setting,
            auth_data: otp_token.into(),
            sessions,
        })
    }

    async fn fetch_user_auth(
        &self,
        user_auth_model: user_authentication::Model,
    ) -> Result<UserAuthentication, DomainError> {
        let user_id = user_auth_model.user_id.clone();

        let base_future = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(user_id.clone()))
            .one(&*self.db);

        let security_settings_future = entity::user_security_settings::Entity::find()
            .filter(entity::user_security_settings::Column::UserId.eq(user_id.clone()))
            .one(&*self.db);

        let sessions_future = entity::user_session::Entity::find()
            .filter(user_session::Column::UserId.eq(user_id.clone()))
            .all(&*self.db);

        let (user_model, user_security_settings, user_sessions) =
            tokio::try_join!(base_future, security_settings_future, sessions_future)?;

        let user_model = user_model.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve("User not found".to_string()))
        })?;

        let security_setting = user_security_settings.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Security settings not found".to_string(),
            ))
        })?;

        let sessions: Vec<UserSession> = user_sessions.into_iter().map(UserSession::from).collect();

        Ok(UserAuthentication {
            user_id: user_model.user_id,
            username: Username::new(&user_model.username),
            email: Email::new(&user_model.email),
            pass_hash: user_model.pass_hash,
            email_validated: user_model.email_validated,
            security_setting: security_setting.into(),
            auth_data: user_auth_model.into(),
            sessions,
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
