use crate::application::dto::user::user_security_request_dto::{
    ActivateEmail2FARequest, ChangeEmailRequest, ChangePasswordRequest, ConfirmApp2FARequest,
    ConfirmDeleteUserRequest, ConfirmEmail2FARequest, ConfirmEmailRequest,
    SecuritySettingsUpdateRequest,
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
use qrcode::render::svg;
use qrcode::QrCode;
use std::io;
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

    pub async fn confirm_enable_email_2fa(
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

    pub async fn enable_app_2fa(
        &self,
        request: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user_id = UserId::new(&request.user_id);
        let response = self.user_security_service.enable_app_2fa(user_id).await?;

        // Send an email with the confirmation token and instructions
        let subject = "Enable Two-Factor Authentication (2FA)";
        let message = format!(
            "To confirm enabling Two-Factor Authentication, please enter the following code: {}\n\n\
        Additionally, to set up 2FA using an authenticator app like Google Authenticator, follow these steps:\n\
        1. Download and install an authenticator app (e.g., Google Authenticator, Authy) on your smartphone.\n\
        2. Open the app and select 'Set up account' or the '+' icon to add a new account.\n\
        3. Choose 'Scan a barcode' and use your phone's camera to scan the QR code provided in your account settings, or enter the following secret key manually: {}\n\
        4. After adding the account, your authenticator app will generate a 6-digit code which you will use for logging in.",
            response.token.value(),
            response.secret
        );

        let qr_code_svg = Self::generate_qr_code_svg(&response.totp_uri).map_err(|_| {
            ApplicationError::ExternalServiceError("Failed to generate QR code.".to_string())
        })?;

        self.email_service
            .send_email_with_attachment(
                response.email.value(),
                &subject,
                &message,
                qr_code_svg,
                "qr_code.svg",
            )
            .await
            .map_err(|_| {
                ApplicationError::ExternalServiceError(
                    "Failed to send the confirmation email for enabling 2FA.".to_string(),
                )
            })?;

        Ok(UniversalApplicationResponse::new(
            "A confirmation code and instructions to enable Two-Factor Authentication (2FA) have been sent to your email.".to_string(),
            None,
        ))
    }

    pub async fn confirm_enable_app_2fa(
        &self,
        request: ConfirmApp2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        self.user_security_service
            .confirm_enable_app_2fa(request.into())
            .await
            .map_err(|e| {
                ApplicationError::ExternalServiceError(format!(
                    "Failed to confirm enabling 2FA: {}",
                    e
                ))
            })?;

        Ok(UniversalApplicationResponse::new(
            "Two-Factor Authentication (2FA) has been successfully enabled.".to_string(),
            None,
        ))
    }

    pub async fn disable_app_2fa(
        &self,
        request: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user_id = UserId::new(&request.user_id);
        let response = self.user_security_service.disable_app_2fa(user_id).await?;

        let subject = "Disable Two-Factor Authentication (2FA)";
        let message = format!(
            "Please confirm disabling Two-Factor Authentication by entering the following code: {}",
            response.token.value()
        );

        self.email_service
            .send_email(response.email.value(), &subject, &message)
            .await
            .map_err(|_| {
                ApplicationError::ExternalServiceError(
                    "Failed to send the confirmation email for disabling 2FA.".to_string(),
                )
            })?;

        Ok(UniversalApplicationResponse::new(
            "A confirmation code to disable Two-Factor Authentication (2FA) has been sent to your email.".to_string(),
            None,
        ))
    }

    pub async fn confirm_disable_app_2fa(
        &self,
        request: ConfirmApp2FARequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        self.user_security_service
            .confirm_disable_app_2fa(request.into())
            .await
            .map_err(|e| {
                ApplicationError::ExternalServiceError(format!(
                    "Failed to confirm disabling 2FA: {}",
                    e
                ))
            })?;

        Ok(UniversalApplicationResponse::new(
            "Two-Factor Authentication (2FA) has been successfully disabled.".to_string(),
            Some(
                "Note: Disabling 2FA reduces the security of your account. \
                It's recommended to re-enable 2FA to keep your account secure."
                    .to_string(),
            ),
        ))
    }

    pub async fn initiate_delete_user(
        &self,
        request: UserByIdRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user_id = UserId::new(&request.user_id);
        let response = self
            .user_security_service
            .initiate_delete_user(user_id)
            .await?;

        let subject = "Deleting Account Authentication";
        let message = format!(
            "Please confirm deleting account by entering the following code: {}",
            response.token.value()
        );

        self.email_service
            .send_email(response.email.value(), &subject, &message)
            .await
            .map_err(|_| {
                ApplicationError::ExternalServiceError(
                    "Failed to send delete account confirmation email.".to_string(),
                )
            })?;

        Ok(UniversalApplicationResponse::new(
            "A confirmation code to delete your account has been sent to your email.".to_string(),
            None,
        ))
    }

    pub async fn confirm_delete_user(
        &self,
        request: ConfirmDeleteUserRequest,
    ) -> Result<UniversalApplicationResponse, ApplicationError> {
        let user_id = UserId::new(&request.user_id);

        self.user_security_service
            .confirm_remove_user(request.into())
            .await?;

        self.session_manager.invalidate_sessions(&user_id).await?;

        Ok(UniversalApplicationResponse::new(
            "Your account has been successfully deleted.".to_string(),
            None,
        ))
    }
}

impl<S, U, E, SM> UserSecurityApplicationService<S, U, E, SM>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
    E: EmailPort,
    SM: SessionManager + Sync + Send,
{
    fn generate_qr_code_svg(data: &str) -> Result<Vec<u8>, io::Error> {
        let code =
            QrCode::new(data).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let svg_string = code.render::<svg::Color>().build();
        Ok(svg_string.into_bytes())
    }
}
