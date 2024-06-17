use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::todo;

#[async_trait]
pub trait UserSecuritySettingsDomainRepository {
    async fn invalidate_session(&self, user: &UserId, session_id: &str) -> Result<(), DomainError>;
    async fn invalidate_sessions(&self, user: &UserId) -> Result<(), DomainError>;
    async fn get_user_session(
        &self,
        user: &UserId,
        session_id: &str,
    ) -> Result<UserSession, DomainError>;
    async fn get_user_sessions(&self, user: &UserId) -> Result<Vec<UserSession>, DomainError>;

    async fn get_old_passwd(&self, user: &UserId) -> Result<String, DomainError>;
    async fn set_new_password(
        &self,
        user: &UserId,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn get_security_settings(
        &self,
        user: &UserId,
    ) -> Result<UserSecuritySettings, DomainError>;
}
