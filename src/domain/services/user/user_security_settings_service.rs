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
}

impl<S> UserSecuritySettingsDomainService<S> where S: UserSecuritySettingsDomainRepository {}
