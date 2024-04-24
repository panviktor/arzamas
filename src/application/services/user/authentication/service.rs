use crate::application::dto::user::user_authentication_request_dto::{
    LoginUserRequest, OTPVerificationRequest, UserToken,
};
use crate::application::dto::user::user_authentication_response_dto::LoginResponse;
use crate::application::error::error::ApplicationError;
use crate::core::config::APP_SETTINGS;
use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::repositories::user::user_authentication_parameters::{
    ContinueLoginRequestDTO, CreateLoginRequestDTO,
};
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::services::user::user_authentication_service::UserAuthenticationDomainService;
use jsonwebtoken::{EncodingKey, Header};
use secrecy::ExposeSecret;
use std::sync::Arc;

pub struct UserAuthenticationApplicationService<A, E, C>
where
    A: UserAuthenticationDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    user_authentication_domain_service: UserAuthenticationDomainService<A>,
    caching_service: Arc<C>,
    email_service: Arc<E>,
}

impl<A, E, C> UserAuthenticationApplicationService<A, E, C>
where
    A: UserAuthenticationDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    pub fn new(
        user_authentication_domain_service: UserAuthenticationDomainService<A>,
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
        if request.password != request.password_confirm {
            return Err(ApplicationError::ValidationError(
                "Passwords do not match.".to_string(),
            ));
        }

        let user_agent = UserAgent::new(&request.user_agent);
        let ip_address = IPAddress::new(&request.ip_address);

        let create_login = CreateLoginRequestDTO::new(
            request.identifier,
            request.password,
            user_agent,
            ip_address,
            request.persistent,
        );

        let create_login = self
            .user_authentication_domain_service
            .initiate_login(create_login)
            .await
            .map_err(|e| ApplicationError::from(e))?;

        match create_login {
            AuthenticationOutcome::AuthenticatedWithPreferences {
                session,
                email,
                message,
                email_notifications_enabled,
            } => {
                let payload: UserToken = session.clone().into();
                let token = generate_token(&payload).await?;
                self.caching_service
                    .store_user_token(&session.user_id, &token)
                    .await?;

                if email_notifications_enabled {
                    self.email_service
                        .send_email(email.value(), "Success Login to Arzamas App", &message)
                        .await?;
                }

                Ok(LoginResponse::TokenResponse {
                    token,
                    token_type: "Bearer".to_string(),
                })
            }

            AuthenticationOutcome::RequireEmailVerification {
                user_id,
                email,
                token,
            } => {
                let subject = "Initiate login to your account in Arzamas App";
                let message = format!("Enter your Email code: {}", token.value());

                self.email_service
                    .send_email(email.value(), &subject, &message)
                    .await?;

                Ok(LoginResponse::OTPResponse {
                    user_id,
                    message: "Please check the code sent to your email.".to_string(),
                })
            }

            AuthenticationOutcome::RequireEmailAndAuthenticatorApp {
                user_id,
                email,
                token,
            } => {
                let subject = "Initiate login to your account in Arzamas App";
                let message = format!(
                    "Enter your OTP Code and the Code from Email. Email code: {}",
                    token.value()
                );

                self.email_service
                    .send_email(email.value(), &subject, &message)
                    .await?;

                Ok(LoginResponse::OTPResponse {
                    user_id,
                    message: "Please check your email and the OTP app for codes.".to_string(),
                })
            }

            AuthenticationOutcome::RequireAuthenticatorApp {
                user_id,
                email,
                email_notifications_enabled,
            } => {
                if email_notifications_enabled {
                    let subject = "Initiate login to your account in Arzamas App";
                    let message = "Please authenticate using your Authenticator App.";

                    self.email_service
                        .send_email(email.value(), &subject, &message)
                        .await?;
                }

                Ok(LoginResponse::OTPResponse {
                    user_id,
                    message: "Please authenticate using your app.".to_string(),
                })
            }

            AuthenticationOutcome::AuthenticationFailed {
                email,
                message,
                email_notifications_enabled,
            } => Err(ApplicationError::ValidationError(format!(
                "{}: {:?}",
                message, email
            ))),

            AuthenticationOutcome::AccountTemporarilyLocked { until, message } => Err(
                ApplicationError::ValidationError(format!("{}: {:?}", message, until)),
            ),

            AuthenticationOutcome::PendingVerification { user_id, message } => {
                Ok(LoginResponse::OTPResponse { user_id, message })
            }
        }
    }

    pub async fn continue_login(
        &self,
        request: OTPVerificationRequest,
    ) -> Result<LoginResponse, ApplicationError> {
        let request = ContinueLoginRequestDTO::from(request);

        let response = self
            .user_authentication_domain_service
            .continue_login(request)
            .await
            .map_err(|e| ApplicationError::from(e))?;

        match response {
            AuthenticationOutcome::RequireEmailVerification { .. } => {
                todo!()
            }
            AuthenticationOutcome::RequireAuthenticatorApp { .. } => {
                todo!()
            }
            AuthenticationOutcome::RequireEmailAndAuthenticatorApp { .. } => {
                todo!()
            }
            AuthenticationOutcome::AuthenticatedWithPreferences { .. } => {
                todo!()
            }
            AuthenticationOutcome::AuthenticationFailed { .. } => {
                todo!()
            }
            AuthenticationOutcome::AccountTemporarilyLocked { .. } => {
                todo!()
            }
            AuthenticationOutcome::PendingVerification { .. } => {
                todo!()
            }
        }
    }
}

async fn generate_token(payload: &UserToken) -> Result<String, ApplicationError> {
    let result = jsonwebtoken::encode(
        &Header::default(),
        &payload,
        &EncodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
    )
    .map_err(|e| ApplicationError::InternalServerError(e.to_string()))?;
    Ok(result)
}
