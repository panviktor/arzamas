use crate::application::dto::user::user_authentication_request_dto::{
    LoginUserRequest, OTPVerificationRequest, UserToken,
};
use crate::application::dto::user::user_authentication_response_dto::LoginResponse;
use crate::application::error::error::ApplicationError;
use crate::application::services::user::shared::shared_service::SharedService;
use crate::domain::entities::shared::value_objects::{IPAddress, OtpCode, UserAgent};
use crate::domain::entities::shared::{Email, OtpToken};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_authentication_dto::{
    ContinueLoginRequestDTO, CreateLoginRequestDTO,
};
use crate::domain::ports::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::user::user_authentication_service::UserAuthenticationDomainService;
use chrono::{DateTime, Utc};
use std::sync::Arc;

pub struct UserAuthenticationApplicationService<A, S, E, C>
where
    A: UserAuthenticationDomainRepository,
    S: UserSharedDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    auth_domain_service: UserAuthenticationDomainService<A, S>,
    caching_service: Arc<C>,
    email_service: Arc<E>,
}

impl<A, S, E, C> UserAuthenticationApplicationService<A, S, E, C>
where
    A: UserAuthenticationDomainRepository,
    S: UserSharedDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    pub fn new(
        auth_domain_service: UserAuthenticationDomainService<A, S>,
        caching_service: Arc<C>,
        email_service: Arc<E>,
    ) -> Self {
        Self {
            auth_domain_service,
            caching_service,
            email_service,
        }
    }

    pub async fn initiate_login(
        &self,
        request: LoginUserRequest,
    ) -> Result<LoginResponse, ApplicationError> {
        let create_login_dto = self.create_login_dto(request);

        let auth_outcome = self
            .auth_domain_service
            .initiate_login(create_login_dto)
            .await
            .map_err(ApplicationError::from)?;

        self.handle_authentication_outcome(auth_outcome).await
    }

    fn create_login_dto(&self, request: LoginUserRequest) -> CreateLoginRequestDTO {
        CreateLoginRequestDTO::new(
            request.identifier,
            request.password,
            UserAgent::new(&request.user_agent),
            IPAddress::new(&request.ip_address),
            request.persistent,
        )
    }

    async fn handle_authentication_outcome(
        &self,
        outcome: AuthenticationOutcome,
    ) -> Result<LoginResponse, ApplicationError> {
        match outcome {
            AuthenticationOutcome::AuthenticatedWithPreferences {
                session,
                email,
                message,
                email_notifications_enabled,
            } => {
                self.handle_authenticated_with_preferences(
                    session,
                    email,
                    message,
                    email_notifications_enabled,
                )
                .await
            }
            AuthenticationOutcome::RequireEmailVerification {
                otp_token,
                otp_code,
                email,
            } => {
                self.handle_email_verification(otp_token, otp_code, email)
                    .await
            }
            AuthenticationOutcome::RequireEmailAndAuthenticatorApp {
                otp_token,
                otp_code,
                email,
            } => {
                self.handle_email_and_authenticator_app(otp_token, otp_code, email)
                    .await
            }
            AuthenticationOutcome::RequireAuthenticatorApp {
                otp_token,
                email,
                email_notifications_enabled,
            } => {
                self.handle_authenticator_app(otp_token, email, email_notifications_enabled)
                    .await
            }
            AuthenticationOutcome::AuthenticationFailed {
                email,
                message,
                email_notifications_enabled,
            } => {
                self.handle_authentication_failed(email, message, email_notifications_enabled)
                    .await
            }
            AuthenticationOutcome::PendingVerification { message } => {
                Ok(LoginResponse::PendingResponse { message })
            }
            AuthenticationOutcome::UserEmailConfirmation { email, token } => {
                self.handle_user_email_confirmation(email, token).await
            }
        }
    }

    async fn handle_authenticated_with_preferences(
        &self,
        session: UserSession,
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    ) -> Result<LoginResponse, ApplicationError> {
        let payload = Self::create_user_token(session).await?;
        let exp = payload.exp;
        let user_id = payload.user_id.clone();
        let session_id = payload.session_id.clone();
        let token = SharedService::generate_token(payload).await?;

        self.caching_service
            .store_user_token(&user_id, &session_id, &token, exp)
            .await?;

        if email_notifications_enabled {
            self.email_service
                .send_email(email.value(), "Successful Login to Arzamas App", &message)
                .await?;
        }

        Ok(LoginResponse::TokenResponse {
            token,
            token_type: "Bearer".to_string(),
        })
    }

    async fn handle_email_verification(
        &self,
        otp_token: OtpToken,
        otp_code: OtpCode,
        email: Email,
    ) -> Result<LoginResponse, ApplicationError> {
        let subject = "Initiate login to your account in Arzamas App";
        let message = format!("Enter your Email code: {}", otp_code.value());

        self.email_service
            .send_email(email.value(), &subject, &message)
            .await?;

        Ok(LoginResponse::OTPResponse {
            otp_token: otp_token.into_inner(),
            message: "Please check the code sent to your email.".to_string(),
        })
    }

    async fn handle_email_and_authenticator_app(
        &self,
        otp_token: OtpToken,
        otp_code: OtpCode,
        email: Email,
    ) -> Result<LoginResponse, ApplicationError> {
        let subject = "Initiate login to your account in Arzamas App";
        let message = format!(
            "Enter your OTP Code and the Code from Email. Email code: {}",
            otp_code.value()
        );

        self.email_service
            .send_email(email.value(), &subject, &message)
            .await?;

        Ok(LoginResponse::OTPResponse {
            otp_token: otp_token.into_inner(),
            message: "Please check your email and the OTP app for codes.".to_string(),
        })
    }

    async fn handle_authenticator_app(
        &self,
        otp_token: OtpToken,
        email: Email,
        email_notifications_enabled: bool,
    ) -> Result<LoginResponse, ApplicationError> {
        if email_notifications_enabled {
            let subject = "Initiate login to your account in Arzamas App";
            let message = "Please authenticate using your Authenticator App.";

            self.email_service
                .send_email(email.value(), &subject, &message)
                .await?;
        }

        Ok(LoginResponse::OTPResponse {
            otp_token: otp_token.into_inner(),
            message: "Please authenticate using your app.".to_string(),
        })
    }

    async fn handle_authentication_failed(
        &self,
        email: Email,
        message: String,
        email_notifications_enabled: bool,
    ) -> Result<LoginResponse, ApplicationError> {
        if email_notifications_enabled {
            let subject = "Login Attempt Failed for Arzamas App Account";
            let email_message = format!("Reason: {}", message);

            self.email_service
                .send_email(email.value(), &subject, &email_message)
                .await?;
        }

        Err(ApplicationError::ValidationError(format!(
            "Authentication failed: {}",
            message
        )))
    }

    async fn handle_user_email_confirmation(
        &self,
        email: Email,
        token: OtpToken,
    ) -> Result<LoginResponse, ApplicationError> {
        let subject = "Login Attempt Failed for Your Arzamas App Account";
        let message = format!(
            "The login attempt failed because email verification is required.\
             A new token has been sent: {}",
            token.into_inner()
        );

        self.email_service
            .send_email(email.value(), subject, &message)
            .await
            .map_err(|e| ApplicationError::ExternalServiceError(e.to_string()))?;

        Err(ApplicationError::ValidationError(
            "Email verification is required".to_string(),
        ))
    }

    pub async fn continue_login(
        &self,
        request: OTPVerificationRequest,
    ) -> Result<LoginResponse, ApplicationError> {
        let request = ContinueLoginRequestDTO::from(request);

        let response = self
            .auth_domain_service
            .continue_login(request)
            .await
            .map_err(|e| ApplicationError::from(e))?;

        match response {
            AuthenticationOutcome::AuthenticatedWithPreferences {
                session,
                email,
                message,
                email_notifications_enabled,
            } => {
                let payload = Self::create_user_token(session).await?;
                let exp = payload.exp;
                let user_id = payload.user_id.clone();
                let session_id = payload.session_id.clone();
                let token = SharedService::generate_token(payload).await?;

                self.caching_service
                    .store_user_token(&user_id, &session_id, &token, exp)
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
            AuthenticationOutcome::AuthenticationFailed {
                email,
                message,
                email_notifications_enabled,
            } => {
                if email_notifications_enabled {
                    let subject = "Initiate login to your account in Arzamas App was Failed";
                    let message = format!("Reason: {}", message);

                    self.email_service
                        .send_email(email.value(), &subject, &message)
                        .await?;
                }

                Err(ApplicationError::ValidationError(format!(
                    "{}: {:?}",
                    message, email
                )))
            }
            AuthenticationOutcome::PendingVerification { message } => {
                Ok(LoginResponse::PendingResponse { message })
            }
            // Catch-all for any other combinations, typically should not occur
            _ => Err(ApplicationError::InternalServerError(
                "Currently login not available".to_string(),
            )),
        }
    }
}

impl<A, S, E, C> UserAuthenticationApplicationService<A, S, E, C>
where
    A: UserAuthenticationDomainRepository,
    S: UserSharedDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    pub async fn validate_session_for_user(&self, token: &str) -> Result<String, ApplicationError> {
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

    fn seconds_until(expiration: DateTime<Utc>) -> Result<u64, ApplicationError> {
        let now = Utc::now();

        if expiration <= now {
            Err(ApplicationError::ValidationError(
                "Expiration time must be in the future".to_string(),
            ))
        } else {
            let duration = expiration - now;
            let seconds = duration.num_seconds();

            if seconds >= 0 {
                Ok(seconds as u64)
            } else {
                // Logically, this branch should never be reached
                Err(ApplicationError::InternalServerError(
                    "Failed to calculate time duration".to_string(),
                ))
            }
        }
    }

    async fn create_user_token(session: UserSession) -> Result<UserToken, ApplicationError> {
        let exp_seconds = Self::seconds_until(session.expiry)?;
        let exp = Utc::now().timestamp() as u64 + exp_seconds;
        let payload = UserToken {
            user_id: session.user_id,
            session_id: session.session_id,
            session_name: session.session_name,
            login_timestamp: session.login_timestamp,
            user_agent: session.user_agent.into_inner(),
            ip_address: session.ip_address.into_inner(),
            exp,
        };
        Ok(payload)
    }
}
