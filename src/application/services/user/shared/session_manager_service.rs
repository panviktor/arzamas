use crate::application::error::error::ApplicationError;
use crate::application::services::user::shared::shared_service::SharedService;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait SessionManager {
    async fn validate_session_for_user(&self, token: &str) -> Result<String, ApplicationError>;
    async fn invalidate_sessions(&self, user_id: &UserId) -> Result<(), ApplicationError>;
    async fn invalidate_session(
        &self,
        user_id: &UserId,
        session_id: &str,
    ) -> Result<(), ApplicationError>;
}

pub struct DefaultSessionManager<S, C>
where
    S: UserSecuritySettingsDomainRepository + Sync + Send,
    C: CachingPort + Sync + Send,
{
    user_security_service: Arc<S>,
    caching_service: Arc<C>,
}

impl<S, C> DefaultSessionManager<S, C>
where
    S: UserSecuritySettingsDomainRepository + Sync + Send,
    C: CachingPort + Sync + Send,
{
    pub fn new(user_security_service: Arc<S>, caching_service: Arc<C>) -> Self {
        Self {
            user_security_service,
            caching_service,
        }
    }
}

#[async_trait]
impl<S, C> SessionManager for DefaultSessionManager<S, C>
where
    S: UserSecuritySettingsDomainRepository + Sync + Send,
    C: CachingPort + Sync + Send,
{
    async fn validate_session_for_user(&self, token: &str) -> Result<String, ApplicationError> {
        let decoded_token = SharedService::decode_token(token)?;
        let user_id = &decoded_token.user_id;
        let active_tokens = self
            .caching_service
            .get_user_sessions_tokens(user_id)
            .await?;

        if active_tokens.contains(&token.to_string()) {
            Ok(user_id.to_string())
        } else {
            Err(ApplicationError::ValidationError(
                "Invalid session token".to_string(),
            ))
        }
    }

    async fn invalidate_sessions(&self, user_id: &UserId) -> Result<(), ApplicationError> {
        self.caching_service
            .invalidate_sessions(&user_id.user_id)
            .await?;
        self.user_security_service
            .invalidate_sessions(user_id)
            .await?;
        Ok(())
    }

    async fn invalidate_session(
        &self,
        user_id: &UserId,
        session_id: &str,
    ) -> Result<(), ApplicationError> {
        self.caching_service
            .invalidate_session(&user_id.user_id, session_id)
            .await?;
        self.user_security_service
            .invalidate_session(user_id, session_id)
            .await?;
        Ok(())
    }
}
