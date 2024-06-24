use crate::application::dto::user::user_recovery_request_dto::{
    UserCompleteRecoveryRequest, UserRecoveryRequest,
};
use crate::application::dto::user::user_shared_response_dto::UniversalApplicationResponse;
use crate::application::error::error::ApplicationError;
use crate::application::services::user::shared::session_manager_service::SessionManager;
use crate::domain::entities::shared::value_objects::{IPAddress, OtpToken, UserAgent, UserId};
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_recovery_password_dto::{
    RecoveryPasswdRequestDTO, RecoveryPasswdResponse, UserCompleteRecoveryRequestDTO,
    UserRecoveryPasswdOutcome,
};
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::services::user::user_recovery_password_service::UserRecoveryPasswordDomainService;
use std::sync::Arc;

pub struct UserRecoveryApplicationService<R, S, E, SM>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
    E: EmailPort,
    SM: SessionManager + Sync + Send,
{
    user_recovery_service: UserRecoveryPasswordDomainService<R, S>,
    session_manager: Arc<SM>,
    email_service: Arc<E>,
}

impl<R, S, E, SM> UserRecoveryApplicationService<R, S, E, SM>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
    E: EmailPort,
    SM: SessionManager + Sync + Send,
{
    pub fn new(
        user_recovery_service: UserRecoveryPasswordDomainService<R, S>,
        session_manager: Arc<SM>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            user_recovery_service,
            session_manager,
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
            .user_recovery_service
            .initiate_password_reset(recovery)
            .await?;

        let email_message = self.compose_recovery_email(&response);

        self.email_service
            .send_email(
                response.email.value(),
                "Password Recovery for Arzamas App",
                &email_message,
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
        let email_token = OtpToken::new(&request.token);

        let domain_request = UserCompleteRecoveryRequestDTO::new(
            email_token,
            request.new_password,
            user_agent,
            ip_address,
        );

        let outcome = self
            .user_recovery_service
            .complete_recovery(domain_request)
            .await?;

        self.process_recovery_outcome(outcome).await
    }

    fn compose_recovery_email(&self, response: &RecoveryPasswdResponse) -> String {
        format!(
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
        )
    }

    async fn process_recovery_outcome(
        &self,
        outcome: UserRecoveryPasswdOutcome,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        match outcome {
            UserRecoveryPasswdOutcome::ValidToken {
                user_id,
                email,
                message,
                close_sessions_on_change_password,
            } => {
                if close_sessions_on_change_password {
                    let user = UserId::new(&user_id);
                    self.session_manager.invalidate_sessions(&user).await?;
                }

                self.email_service
                    .send_email(email.value(), "Arzamas App", &message)
                    .await
                    .map_err(|e| ApplicationError::ExternalServiceError(e.to_string()))?;

                Ok(UniversalApplicationResponse {
                    title: "Password Reset Successful".to_string(),
                    subtitle: Some(message.to_string()),
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
