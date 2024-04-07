use crate::application::dto::user::user_authentication_request_dto::{
    LoginUserRequest, OTPCodeRequest,
};
use crate::application::dto::user::user_authentication_response_dto::LoginResponse;
use crate::application::error::error::ApplicationError;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::DomainError;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::repositories::user::user_shared_repository::UserDomainRepository;
use crate::domain::services::user::user_authentication_service::UserAuthenticationDomainService;
use std::sync::Arc;

pub struct UserAuthenticationApplicationService<A, U, E, C>
where
    A: UserAuthenticationDomainRepository,
    U: UserDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    user_authentication_domain_service: UserAuthenticationDomainService<A, U>,
    caching_service: Arc<C>,
    email_service: Arc<E>,
}

impl<A, U, E, C> UserAuthenticationApplicationService<A, U, E, C>
where
    A: UserAuthenticationDomainRepository,
    U: UserDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    pub fn new(
        user_authentication_domain_service: UserAuthenticationDomainService<A, U>,
        caching_service: Arc<C>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            user_authentication_domain_service,
            caching_service,
            email_service,
        }
    }

    pub async fn initiate_login(
        &self,
        request: LoginUserRequest,
    ) -> Result<LoginResponse, ApplicationError> {
        todo!()
    }

    pub async fn continue_login(
        &self,
        request: OTPCodeRequest,
    ) -> Result<LoginResponse, ApplicationError> {
        todo!()
    }
}
