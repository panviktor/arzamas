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
use crate::application::services::user::shared::session_manager_service::SessionManager;
use crate::application::services::user::shared::shared_service::SharedService;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::user::user_security_settings_service::UserSecuritySettingsDomainService;
use std::sync::Arc;
use tokio::join;

pub struct UserSecurityApplicationService<S, U, E, SM>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
    E: EmailPort,
    SM: SessionManager + Sync + Send,
{
    user_security_service: UserSecuritySettingsDomainService<S, U>,
    session_manager: Arc<SM>,
    email_service: Arc<E>,
}

impl<S, U, E, SM> UserSecurityApplicationService<S, U, E, SM>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
    E: EmailPort,
    SM: SessionManager + Sync + Send,
{
    pub fn new(
        user_security_service: UserSecuritySettingsDomainService<S, U>,
        session_manager: Arc<SM>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            user_security_service,
            session_manager,
            email_service,
        }
    }
    pub async fn logout_all_sessions(
        &self,
        request: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user = UserId::new(&request.user_id);
        self.session_manager.invalidate_sessions(&user).await?;
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
        self.session_manager
            .invalidate_session(&user, &decoded_token.session_id)
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
            .user_security_service
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
            .user_security_service
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
        self.user_security_service
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
        if request.new_email != request.new_email_confirm {
            return Err(ApplicationError::ValidationError(
                "The new email addresses do not match.".to_string(),
            ));
        }

        let response = self
            .user_security_service
            .change_email(request.into())
            .await?;

        let subject_old = "Action Required: Email Change Request";
        let message_old = "A request to change your email address has been initiated.\n
         If you did not request this change, please contact support immediately.\n
         If you did request this change, please check your new email for the confirmation code."
            .to_string();

        let old_future =
            self.email_service
                .send_email(response.old_email.value(), &subject_old, &message_old);

        let subject_old = "Complete Your Email Change Request";
        let message_old = format!(
            "Please confirm your email address change by entering the following code: {:?}",
            response.email_validation_token
        );

        let new_future =
            self.email_service
                .send_email(response.new_email.value(), &subject_old, &message_old);

        let (old_email_result, new_email_result) = join!(old_future, new_future);
        if let Err(_) = old_email_result {
            return Err(ApplicationError::ExternalServiceError(
                "Failed to send email to old email address.".to_string(),
            ));
        }

        if let Err(_) = new_email_result {
            return Err(ApplicationError::ExternalServiceError(
                "Failed to send email to new email address.".to_string(),
            ));
        }

        Ok(UniversalApplicationResponse::new(
            "Email change initiated successfully.".to_string(),
            None,
        ))
    }

    pub async fn cancel_email_change(
        &self,
        user: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user = UserId::new(&user.user_id);
        self.user_security_service.cancel_email_change(user).await?;
        Ok(UniversalApplicationResponse::new(
            "Email change canceled successfully.".to_string(),
            None,
        ))
    }

    pub async fn confirm_email(
        &self,
        request: ConfirmEmailRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        self.user_security_service
            .confirm_email(request.into())
            .await?;
        Ok(UniversalApplicationResponse::new(
            "Your email address has been successfully confirmed and updated.".to_string(),
            None,
        ))
    }

    pub async fn get_security_settings(
        &self,
        user: UserByIdRequest,
    ) -> Result<SecuritySettingsResponse, ApplicationError> {
        let user = UserId::new(&user.user_id);
        let response = self
            .user_security_service
            .get_security_settings(user)
            .await?;
        Ok(response.into())
    }

    pub async fn update_security_settings(
        &self,
        request: SecuritySettingsUpdateRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        self.user_security_service
            .update_security_settings(request.into())
            .await?;
        Ok(UniversalApplicationResponse::new(
            "Your security settings have been successfully updated.".to_string(),
            None,
        ))
    }

    pub async fn enable_email_2fa(
        &self,
        request: ActivateEmail2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let response = self
            .user_security_service
            .enable_email_2fa(request.into())
            .await?;

        // Send an email with the confirmation token
        let subject = "Enable 2FA Email Authentication";
        let message = format!(
            "Please confirm enabling 2FA by entering the following code: {}",
            response.token.value()
        );

        self.email_service
            .send_email(response.email.value(), &subject, &message)
            .await
            .map_err(|_| {
                ApplicationError::ExternalServiceError(
                    "Failed to send 2FA enable confirmation email.".to_string(),
                )
            })?;

        Ok(UniversalApplicationResponse::new(
            "A confirmation code to enable 2FA has been sent to your email.".to_string(),
            None,
        ))
    }

    pub async fn confirm_email_2fa(
        &self,
        request: ConfirmEmail2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        self.user_security_service
            .confirm_email_2fa(request.into())
            .await?;
        Ok(UniversalApplicationResponse::new(
            "2FA email authentication has been successfully enabled.".to_string(),
            None,
        ))
    }

    pub async fn disable_email_2fa(
        &self,
        request: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user_id = UserId::new(&request.user_id);

        let response = self
            .user_security_service
            .disable_email_2fa(user_id)
            .await?;

        // Send an email with the confirmation token
        let subject = "Disable 2FA Email Authentication";
        let message = format!(
            "Please confirm disabling 2FA by entering the following code: {}",
            response.token.value()
        );

        self.email_service
            .send_email(response.email.value(), &subject, &message)
            .await
            .map_err(|_| {
                ApplicationError::ExternalServiceError(
                    "Failed to send 2FA disable confirmation email.".to_string(),
                )
            })?;

        Ok(UniversalApplicationResponse::new(
            "A confirmation code to disable 2FA has been sent to your email.".to_string(),
            None,
        ))
    }

    pub async fn confirm_disable_email_2fa(
        &self,
        request: ConfirmEmail2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        self.user_security_service
            .confirm_disable_email_2fa(request.into())
            .await?;
        Ok(UniversalApplicationResponse::new(
            "2FA email authentication has been successfully disabled.".to_string(),
            None,
        ))
    }
}
