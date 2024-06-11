use crate::application::dto::user::user_shared_request_dto::UserByIdRequest;
use crate::application::error::error::ApplicationError;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::FindUserByIdDTO;
use crate::domain::services::user::user_security_settings_service::UserSecuritySettingsDomainService;
use std::sync::Arc;

pub struct UserSecurityApplicationService<S, E, C>
where
    S: UserSecuritySettingsDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    user_security_domain_service: UserSecuritySettingsDomainService<S>,
    caching_service: Arc<C>,
    email_service: Arc<E>,
}

impl<S, E, C> UserSecurityApplicationService<S, E, C>
where
    S: UserSecuritySettingsDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    pub fn new(
        user_security_domain_service: UserSecuritySettingsDomainService<S>,
        caching_service: Arc<C>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            user_security_domain_service,
            caching_service,
            email_service,
        }
    }

    pub async fn logout_all_sessions(
        &self,
        request: UserByIdRequest,
    ) -> Result<(), ApplicationError> {
        let user = FindUserByIdDTO::new(&request.user_id);
        self.caching_service
            .invalidate_sessions(&user.user_id)
            .await?;
        self.user_security_domain_service
            .invalidate_sessions(user)
            .await?;
        Ok(())
    }

    pub async fn logout_current_session(
        &self,
        user: UserByIdRequest,
        session_token: String,
    ) -> Result<(), ApplicationError> {
        let user = FindUserByIdDTO::new(&user.user_id);
        todo!()
    }
}
