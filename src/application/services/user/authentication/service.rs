use crate::application::dto::user::user_authentication_request_dto::{
    LoginUserRequest, OTPVerificationRequest, UserToken,
};
use crate::application::dto::user::user_authentication_response_dto::LoginResponse;
use crate::application::error::error::ApplicationError;
use crate::core::config::APP_SETTINGS;
use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::ports::repositories::user::user_authentication_parameters::{
    ContinueLoginRequestDTO, CreateLoginRequestDTO,
};
use crate::domain::ports::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::services::user::user_authentication_service::UserAuthenticationDomainService;
use chrono::{DateTime, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
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
                let payload = create_user_token(session).await?;
                let exp = payload.exp;
                let user_id = payload.user_id.clone();
                let session_id = payload.session_id.clone();
                let token = generate_token(payload).await?;

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
            AuthenticationOutcome::AuthenticatedWithPreferences {
                session,
                email,
                message,
                email_notifications_enabled,
            } => {
                let payload = create_user_token(session).await?;
                let exp = payload.exp;
                let user_id = payload.user_id.clone();
                let session_id = payload.session_id.clone();
                let token = generate_token(payload).await?;

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
            AuthenticationOutcome::PendingVerification { user_id, message } => {
                Ok(LoginResponse::OTPResponse { user_id, message })
            }
            // Catch-all for any other combinations, typically should not occur
            _ => Err(ApplicationError::InternalServerError(
                "Currently login not available".to_string(),
            )),
        }
    }
}

impl<A, E, C> UserAuthenticationApplicationService<A, E, C>
where
    A: UserAuthenticationDomainRepository,
    E: EmailPort,
    C: CachingPort,
{
    pub async fn validate_session_for_user(&self, token: &str) -> Result<String, ApplicationError> {
        let decoded_token = decode_token(token)?;
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
}

async fn generate_token(payload: UserToken) -> Result<String, ApplicationError> {
    let header = Header::new(Algorithm::HS512);
    let result = jsonwebtoken::encode(
        &header,
        &payload,
        &EncodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
    )
    .map_err(|e| ApplicationError::InternalServerError(e.to_string()))?;
    Ok(result)
}

fn decode_token(token: &str) -> Result<UserToken, ApplicationError> {
    let token = decode::<UserToken>(
        token,
        &DecodingKey::from_secret(APP_SETTINGS.jwt_secret.expose_secret().as_ref()),
        &Validation::new(Algorithm::HS512),
    )
    .map_err(|e| match e.kind() {
        ErrorKind::InvalidToken => ApplicationError::ValidationError("Invalid token".to_string()),
        ErrorKind::ExpiredSignature => {
            ApplicationError::ValidationError("Token has expired".to_string())
        }
        ErrorKind::InvalidIssuer => ApplicationError::ValidationError("Invalid issuer".to_string()),
        ErrorKind::InvalidAudience => {
            ApplicationError::ValidationError("Invalid audience".to_string())
        }
        _ => ApplicationError::InternalServerError(e.to_string()),
    })
    .map(|token_data| token_data.claims)?;

    Ok(token)
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
            // Logically this branch should never be reached
            Err(ApplicationError::InternalServerError(
                "Failed to calculate time duration".to_string(),
            ))
        }
    }
}

async fn create_user_token(session: UserSession) -> Result<UserToken, ApplicationError> {
    let exp_seconds = seconds_until(session.expiry)?;
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
