use crate::application::dto::user::user_security_request_dto::{
    ActivateEmail2FARequest, ChangeEmailRequest, ChangePasswordRequest, ConfirmEmail2FARequest,
    ConfirmEmailRequest, SecuritySettingsUpdateRequest,
};
use crate::application::dto::user::user_security_response_dto::{
    SecuritySettingsResponse, UserSessionResponse,
};
use crate::application::dto::user::user_shared_request_dto::UserByIdRequest;
use crate::application::dto::user::user_shared_response_dto::UniversalApplicationResponse;
use crate::application::error::error::ApplicationError;
use crate::application::services::user::shared::shared_service::SharedService;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
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
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user = UserId::new(&request.user_id);
        self.caching_service
            .invalidate_sessions(&user.user_id)
            .await?;
        self.user_security_domain_service
            .invalidate_sessions(user)
            .await?;
        Ok(UniversalApplicationResponse::new(
            "You have successfully logged out of all active sessions.".to_string(),
            None,
        ))
    }

    pub async fn logout_current_session(
        &self,
        user: UserByIdRequest,
        session_token: &str,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user = UserId::new(&user.user_id);
        let decoded_token = SharedService::decode_token(session_token)?;
        self.caching_service
            .invalidate_session(&user.user_id, &decoded_token.session_id)
            .await?;
        self.user_security_domain_service
            .invalidate_session(user, &decoded_token.session_id)
            .await?;

        Ok(UniversalApplicationResponse::new(
            "You have successfully logged out of the current active session.".to_string(),
            None,
        ))
    }
    pub async fn get_user_session(
        &self,
        user: UserByIdRequest,
        session_token: &str,
    ) -> Result<UserSessionResponse, ApplicationError> {
        let user = UserId::new(&user.user_id);
        let decoded_token = SharedService::decode_token(session_token)?;
        let session = self
            .user_security_domain_service
            .get_user_session(user, &decoded_token.session_id)
            .await?
            .into();
        Ok(session)
    }

    pub async fn get_user_sessions(
        &self,
        user: UserByIdRequest,
    ) -> Result<Vec<UserSessionResponse>, ApplicationError> {
        let user = UserId::new(&user.user_id);
        let sessions = self
            .user_security_domain_service
            .get_user_sessions(user)
            .await?
            .into_iter()
            .map(UserSessionResponse::from)
            .collect();
        Ok(sessions)
    }

    pub async fn change_password(
        &self,
        request: ChangePasswordRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        if request.new_password != request.new_password_confirm {
            return Err(ApplicationError::ValidationError(
                "Passwords do not match.".to_string(),
            ));
        }
        self.user_security_domain_service
            .change_password(request.into())
            .await?;
        Ok(UniversalApplicationResponse::new(
            "Password change successfully".to_string(),
            None,
        ))
    }

    pub async fn change_email(
        &self,
        request: ChangeEmailRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        todo!()
    }

    pub async fn confirm_email(
        &self,
        request: ConfirmEmailRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        todo!()
    }

    pub async fn get_security_settings(
        &self,
        user: UserByIdRequest,
    ) -> Result<SecuritySettingsResponse, ApplicationError> {
        todo!()
    }

    pub async fn update_security_settings(
        &self,
        request: SecuritySettingsUpdateRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        todo!()
    }

    pub async fn enable_email_2fa(
        &self,
        request: ActivateEmail2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        // code to activate email 2fa is send to your email

        todo!()
    }

    pub async fn resend_email_2fa(
        &self,
        request: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        // code to activate email 2fa is resend to your email

        todo!()
    }

    pub async fn confirm_email_2fa(
        &self,
        request: ConfirmEmail2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        // Sending an authorization code by email is activated

        todo!()
    }

    pub async fn disable_email_2fa(
        &self,
        request: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        // code to deactivate email 2fa is send to your email if email was activated else reset status from waiting token to None
        todo!()
    }

    pub async fn confirm_disable_email_2fa(
        &self,
        request: ConfirmEmail2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        // Sending an authorization code by email is off
        todo!()
    }
}
