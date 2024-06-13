use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::FindUserByIdDTO;
use std::sync::Arc;

pub struct UserSecuritySettingsDomainService<S>
where
    S: UserSecuritySettingsDomainRepository,
{
    user_security_settings_repository: Arc<S>,
}

impl<S> UserSecuritySettingsDomainService<S>
where
    S: UserSecuritySettingsDomainRepository,
{
    pub fn new(user_security_settings_repository: Arc<S>) -> Self {
        Self {
            user_security_settings_repository,
        }
    }

    pub async fn invalidate_sessions(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        self.user_security_settings_repository
            .invalidate_sessions(&user)
            .await
    }

    pub async fn invalidate_session(
        &self,
        user: FindUserByIdDTO,
        session_id: &str,
    ) -> Result<(), DomainError> {
        self.user_security_settings_repository
            .invalidate_session(&user, session_id)
            .await
    }

    pub async fn get_user_session(
        &self,
        user: FindUserByIdDTO,
        session_id: &str,
    ) -> Result<UserSession, DomainError> {
        let session = self
            .user_security_settings_repository
            .get_user_session(&user, session_id)
            .await?;
        Ok(session)
    }

    pub async fn get_user_sessions(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<Vec<UserSession>, DomainError> {
        let sessions = self
            .user_security_settings_repository
            .get_user_sessions(&user)
            .await?;
        Ok(sessions)
    }
}
