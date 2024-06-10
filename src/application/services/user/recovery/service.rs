use crate::application::dto::user::user_recovery_request_dto::{
    UserCompleteRecoveryRequest, UserRecoveryRequest,
};
use crate::application::dto::user::user_shared_response_dto::UniversalApplicationResponse;
use crate::application::error::error::ApplicationError;
use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_recovery_password_parameters::{
    RecoveryPasswdRequestDTO, UserCompleteRecoveryRequestDTO, UserRecoveryPasswdOutcome,
};
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::services::user::user_recovery_password_service::UserRecoveryPasswordDomainService;
use std::sync::Arc;

pub struct UserRecoveryApplicationService<R, S, E, C>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    user_recovery_domain_service: UserRecoveryPasswordDomainService<R, S>,
    caching_service: Arc<C>,
    email_service: Arc<E>,
}

impl<R, S, E, C> UserRecoveryApplicationService<R, S, E, C>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    pub fn new(
        user_recovery_domain_service: UserRecoveryPasswordDomainService<R, S>,
        caching_service: Arc<C>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            user_recovery_domain_service,
            caching_service,
            email_service,
        }
    }

    pub async fn initiate_recovery(
        &self,
        request: UserRecoveryRequest,
    ) -> Result<(), ApplicationError> {
        let user_agent = UserAgent::new(&request.user_agent);
        let ip_address = IPAddress::new(&request.ip_address);

        let recovery = RecoveryPasswdRequestDTO::new(request.identifier, user_agent, ip_address);

        let response = self
            .user_recovery_domain_service
            .initiate_password_reset(recovery)
            .await?;

        // Generate the email content
        let message = format!(
            "Dear {},\n\n\
            You requested a password reset for your account. \
            Please use the following token to reset your password: {}\n\n\
            This token will expire at: {}.\n\n\
            If you did not request this, please ignore this email.\n\n\
            Best regards,\n\
            Arzamas App Team",
            response.username.value(),
            response.token.value(),
            response.expiry.to_rfc3339()
        );

        // Send the email
        self.email_service
            .send_email(
                response.email.value(),
                "Password Recovery for Arzamas App",
                &message,
            )
            .await?;

        Ok(())
    }

    pub async fn complete_recovery(
        &self,
        request: UserCompleteRecoveryRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        if request.new_password != request.password_confirm {
            return Err(ApplicationError::ValidationError(
                "Passwords do not match.".to_string(),
            ));
        }

        let user_agent = UserAgent::new(&request.user_agent);
        let ip_address = IPAddress::new(&request.ip_address);
        let email_token = EmailToken::new(&request.token);

        let domain_request = UserCompleteRecoveryRequestDTO::new(
            email_token,
            request.new_password,
            user_agent,
            ip_address,
        );

        let outcome = self
            .user_recovery_domain_service
            .complete_recovery(domain_request)
            .await?;

        match outcome {
            UserRecoveryPasswdOutcome::ValidToken {
                user_id,
                email,
                message,
                close_sessions_on_change_password,
            } => {
                if close_sessions_on_change_password {
                    self.caching_service.invalidate_sessions(&user_id).await?;
                }

                self.email_service
                    .send_email(email.value(), "Arzamas App", &message)
                    .await
                    .map_err(|e| ApplicationError::ExternalServiceError(e.to_string()))?;

                Ok(UniversalApplicationResponse {
                    title: "Password Reset Successful".to_string(),
                    subtitle: Some("Your password has been successfully reset.".to_string()),
                })
            }
            UserRecoveryPasswdOutcome::InvalidToken {
                email,
                message,
                email_notifications_enabled,
            } => {
                if email_notifications_enabled {
                    self.email_service
                        .send_email(email.value(), "Arzamas App", &message)
                        .await
                        .map_err(|e| ApplicationError::ExternalServiceError(e.to_string()))?;
                }
                Err(ApplicationError::ValidationError(message))
            }
        }
    }
}
