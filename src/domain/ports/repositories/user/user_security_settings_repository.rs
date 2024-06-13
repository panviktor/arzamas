use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserSecuritySettingsDomainRepository {
    async fn set_new_password(
        &self,
        user: &FindUserByIdDTO,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn invalidate_session(
        &self,
        user: &FindUserByIdDTO,
        session_id: &str,
    ) -> Result<(), DomainError>;

    async fn invalidate_sessions(&self, user: &FindUserByIdDTO) -> Result<(), DomainError>;
    async fn get_user_session(
        &self,
        user: &FindUserByIdDTO,
        session_id: &str,
    ) -> Result<UserSession, DomainError>;
    async fn get_user_sessions(
        &self,
        user: &FindUserByIdDTO,
    ) -> Result<Vec<UserSession>, DomainError>;
}
