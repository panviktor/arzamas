use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::user_security_settings::{
    User2FAEmailConfirmation, UserSecuritySettings,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_security_settings_dto::SecuritySettingsUpdateDTO;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use entity::{user, user_session};
use sea_orm::sea_query::Expr;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, ModelTrait,
    QueryFilter,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmUserSecurityRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserSecurityRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserSecuritySettingsDomainRepository for SeaOrmUserSecurityRepository {
    async fn invalidate_session(&self, user: &UserId, session_id: &str) -> Result<(), DomainError> {
        let session = user_session::Entity::find()
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .filter(user_session::Column::SessionId.eq(session_id))
            .one(&*self.db)
            .await
            .map_err(|_| {
                DomainError::PersistenceError(PersistenceError::Delete(
                    "Database error occurred".to_string(),
                ))
            })?
            .ok_or_else(|| DomainError::NotFound)?;

        let mut active = session.into_active_model();
        active.valid = Set(false);

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn invalidate_sessions(&self, user: &UserId) -> Result<(), DomainError> {
        user_session::Entity::update_many()
            .col_expr(user_session::Column::Valid, Expr::value(false))
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .exec(&*self.db)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;
        Ok(())
    }

    async fn get_user_session(
        &self,
        user: &UserId,
        session_id: &str,
    ) -> Result<UserSession, DomainError> {
        let session = user_session::Entity::find()
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .filter(user_session::Column::SessionId.eq(session_id))
            .one(&*self.db)
            .await
            .map_err(|_| {
                DomainError::PersistenceError(PersistenceError::Delete(
                    "Database error occurred".to_string(),
                ))
            })?
            .ok_or_else(|| DomainError::NotFound)?;
        Ok(session.into())
    }

    async fn get_user_sessions(&self, user: &UserId) -> Result<Vec<UserSession>, DomainError> {
        let sessions: Vec<UserSession> = user_session::Entity::find()
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .all(&*self.db)
            .await
            .map_err(|_| {
                DomainError::PersistenceError(PersistenceError::Delete(
                    "Database error occurred".to_string(),
                ))
            })?
            .into_iter()
            .map(UserSession::from)
            .collect();

        Ok(sessions)
    }

    async fn get_old_passwd(&self, user: &UserId) -> Result<String, DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(&user.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found".to_string(),
                ))
            })?;
        Ok(user_model.pass_hash)
    }

    async fn set_new_password(
        &self,
        user: &UserId,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(&user.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found".to_string(),
                ))
            })?;

        let mut active = user_model.into_active_model();
        active.pass_hash = Set(pass_hash);
        active.updated_at = Set(update_time.naive_utc());
        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn get_security_settings(
        &self,
        user: &UserId,
    ) -> Result<UserSecuritySettings, DomainError> {
        let security_setting = entity::user_security_settings::Entity::find()
            .filter(entity::user_security_settings::Column::UserId.eq(user.user_id.as_str()))
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User security settings not found".to_string(),
                ))
            })?
            .into();
        Ok(security_setting)
    }

    async fn update_security_settings(
        &self,
        settings: SecuritySettingsUpdateDTO,
    ) -> Result<(), DomainError> {
        let ss = entity::user_security_settings::Entity::find()
            .filter(entity::user_security_settings::Column::UserId.eq(settings.user_id.user_id))
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User security settings not found".to_string(),
                ))
            })?;

        let mut active = ss.into_active_model();

        if let Some(email_on_success) = settings.email_on_success {
            active.email_on_success_enabled_at = Set(email_on_success);
        }
        if let Some(email_on_failure) = settings.email_on_failure {
            active.email_on_failure_enabled_at = Set(email_on_failure);
        }
        if let Some(close_sessions_on_change_password) = settings.close_sessions_on_change_password
        {
            active.close_sessions_on_change_password = Set(close_sessions_on_change_password);
        }

        active.update(&*self.db).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(
                "Failed to update user security settings".to_string(),
            ))
        })?;

        Ok(())
    }

    async fn save_email_2fa_token(
        &self,
        user_id: UserId,
        email_token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        todo!()
    }

    async fn retrieve_email_2fa_token(
        &self,
        user: &UserId,
    ) -> Result<User2FAEmailConfirmation, DomainError> {
        todo!()
    }

    async fn toggle_email_2fa(&self, user: &UserId, enable: bool) -> Result<(), DomainError> {
        todo!()
    }
}
