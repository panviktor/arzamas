use crate::application::dto::user::user_authentication_request_dto::{
    LoginUserRequest, OTPCodeRequest, UserToken,
};
use crate::application::dto::user::user_authentication_response_dto::LoginResponse;
use crate::application::error::error::ApplicationError;
use crate::core::config::APP_SETTINGS;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::ports::caching::caching::CachingPort;
use crate::domain::ports::email::email::EmailPort;
use crate::domain::repositories::user::user_authentication_parameters::CreateLoginRequestDTO;
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::services::user::user_authentication_service::UserAuthenticationDomainService;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
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

        let create_login = CreateLoginRequestDTO::new(
            request.identifier,
            request.password,
            request.user_agent,
            request.ip_address,
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
            AuthenticationOutcome::RequireEmailVerification { user_id, email }
            | AuthenticationOutcome::RequireEmailAndAuthenticatorApp { user_id, email } => {
                Ok(LoginResponse::OTPResponse {
                    message: format!("Please verify your email: {:?}", email),
                    apps_code: false,
                    user_id,
                })
            }
            AuthenticationOutcome::RequireAuthenticatorApp {
                user_id,
                email,
                email_notifications_enabled,
            } => Ok(LoginResponse::OTPResponse {
                message: format!(
                    "Please authenticate using your app. Email: {:?}, Notifications enabled: {}",
                    email, email_notifications_enabled
                ),
                apps_code: true,
                user_id,
            }),
            AuthenticationOutcome::AuthenticationFailed { email, message, .. } => Err(
                ApplicationError::ValidationError(format!("{}: {:?}", message, email)),
            ),
        }
    }

    pub async fn continue_login(
        &self,
        request: OTPCodeRequest,
    ) -> Result<LoginResponse, ApplicationError> {
        todo!()
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
