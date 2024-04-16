use crate::core::constants::emojis::EMOJIS;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use std::cmp::PartialEq;

use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::repositories::user::user_authentication_parameters::{
    ContinueLoginRequestDTO, CreateLoginRequestDTO, VerificationMethod,
};
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::user_validation_service::EMAIL_REGEX;
use crate::domain::services::user::{UserCredentialService, UserValidationService};
use chrono::{Duration, Utc};
use uuid::Uuid;

pub struct UserAuthenticationDomainService<R>
where
    R: UserAuthenticationDomainRepository,
{
    user_authentication_repository: R,
}

impl<R> UserAuthenticationDomainService<R>
where
    R: UserAuthenticationDomainRepository,
{
    pub fn new(user_authentication_repository: R) -> Self {
        Self {
            user_authentication_repository,
        }
    }
    pub async fn initiate_login(
        &self,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let identifier = &request.identifier;
        let user_result = self.identify_user(identifier).await?;
        self.check_account_blocked(&user_result)?;
        self.process_login_attempt(&user_result, request).await
    }

    pub async fn continue_login(
        &self,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let identifier = &request.identifier;
        let user_result = self.identify_user(identifier).await?;
        self.check_account_blocked(&user_result)?;

        if self.is_request_from_trusted_source(&request, &user_result) {
            match request.verification_method {
                VerificationMethod::EmailOTP => self.verify_email_otp(&user_result, request).await,
                VerificationMethod::AuthenticatorApp => {
                    self.verify_authenticator_app(&user_result, request).await
                }
            }
        } else {
            let message = "IP address or user agent mismatch.";
            self.handle_failed_login_attempt(&user_result, message)
                .await
        }
    }
}

impl<R> UserAuthenticationDomainService<R>
where
    R: UserAuthenticationDomainRepository,
{
    fn generate_session_name() -> String {
        use rand::seq::SliceRandom;
        let mut rng = &mut rand::thread_rng();
        EMOJIS
            .choose_multiple(&mut rng, 5)
            .cloned()
            .collect::<String>()
            .to_string()
    }

    async fn identify_user(&self, identifier: &str) -> Result<UserAuthentication, DomainError> {
        if EMAIL_REGEX.is_match(identifier) {
            UserValidationService::validate_email(&Email::new(identifier))?;
            self.user_authentication_repository
                .get_user_by_email(FindUserByEmailDTO {
                    email: Email::new(identifier),
                })
                .await
        } else {
            UserValidationService::validate_username(&Username::new(identifier))?;
            self.user_authentication_repository
                .get_user_by_username(FindUserByUsernameDTO {
                    username: Username::new(identifier),
                })
                .await
        }
    }

    fn check_account_blocked(&self, user_result: &UserAuthentication) -> Result<(), DomainError> {
        if let Some(blocked_until) = user_result.login_blocked_until {
            let now = Utc::now();
            if now < blocked_until {
                let friendly_date = blocked_until.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                return Err(DomainError::ValidationError(
                    ValidationError::BusinessRuleViolation(format!(
                        "Your account is locked until {}",
                        friendly_date
                    )),
                ));
            }
        }
        Ok(())
    }

    async fn process_login_attempt(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        UserValidationService::validate_password(&request.password)?;

        if !UserCredentialService::credential_validator(&user.pass_hash, &request.password)? {
            let message = "Incorrect password.";
            self.handle_failed_login_attempt(user, message).await
        } else {
            self.handle_successful_login_attempt(user, request).await
        }
    }

    async fn handle_failed_login_attempt(
        &self,
        user: &UserAuthentication,
        message: &str,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let attempt_count = user.attempt_count + 1;
        let user_id = FindUserByIdDTO::new(&user.user_id);

        let block_duration = if attempt_count > 10 {
            Some(Utc::now() + Duration::hours(3))
        } else if attempt_count > 5 {
            Some(Utc::now() + Duration::minutes(15))
        } else {
            None
        };

        self.user_authentication_repository
            .block_user_until(&user_id, block_duration)
            .await?;

        self.user_authentication_repository
            .update_user_login_attempts(user_id, attempt_count)
            .await?;

        Ok(AuthenticationOutcome::AuthenticationFailed {
            email: user.email.clone(),
            message: message.to_string(),
            email_notifications_enabled: user.security_setting.email_on_failure_enabled_at,
        })
    }

    async fn handle_successful_login_attempt(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        match (
            user.security_setting.two_factor_email,
            user.security_setting.two_factor_authenticator_app,
        ) {
            (true, true) => {
                // Both two-factor authentication methods are enabled
                // Handle case where both email and authenticator app verification are required
                let duration = Duration::minutes(10);
                let confirmation_token = self
                    .generate_and_prepare_token(
                        &user.user_id,
                        duration,
                        request.user_agent,
                        request.ip_address,
                    )
                    .await?;
                Ok(AuthenticationOutcome::RequireEmailAndAuthenticatorApp {
                    user_id: user.user_id.clone(),
                    email: user.email.clone(),
                    token: confirmation_token,
                    email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
                })
            }
            (true, false) => {
                // Only two-factor email authentication is enabled
                // Handle case where only email verification is required
                let duration = Duration::minutes(10);
                let confirmation_token = self
                    .generate_and_prepare_token(
                        &user.user_id,
                        duration,
                        request.user_agent,
                        request.ip_address,
                    )
                    .await?;
                Ok(AuthenticationOutcome::RequireEmailVerification {
                    user_id: user.user_id.clone(),
                    email: user.email.clone(),
                    token: confirmation_token,
                    email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
                })
            }
            (false, true) => {
                // Only two-factor authenticator app authentication is enabled
                // Handle case where only authenticator app verification is required
                let user_id = FindUserByIdDTO::new(&user.user_id);
                let expiry_duration = Duration::minutes(5);
                self.prepare_2fa(
                    user_id,
                    expiry_duration,
                    request.user_agent,
                    request.ip_address,
                )
                .await?;

                Ok(AuthenticationOutcome::RequireAuthenticatorApp {
                    user_id: user.user_id.clone(),
                    email: user.email.clone(),
                    email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
                })
            }
            (false, false) => {
                self.create_session_for_user(
                    user,
                    request.persistent,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
        }
    }

    async fn prepare_2fa(
        &self,
        user_id: FindUserByIdDTO,
        expiry_duration: Duration,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError> {
        let expiry = Utc::now() + expiry_duration;
        self.user_authentication_repository
            .prepare_user_for_2fa(user_id, expiry, None, user_agent, ip_address)
            .await
    }

    async fn generate_and_prepare_token(
        &self,
        user_id: &str,
        duration: Duration,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<EmailToken, DomainError> {
        let token = SharedDomainService::generate_token(6)?;
        let confirmation_token = EmailToken::new(&token);
        let confirmation_token_hash = SharedDomainService::hash_token(&token);

        let user_id_dto = FindUserByIdDTO::new(user_id);
        self.user_authentication_repository
            .prepare_user_for_2fa(
                user_id_dto,
                Utc::now() + duration,
                Some(confirmation_token_hash),
                user_agent,
                ip_address,
            )
            .await?;

        Ok(confirmation_token)
    }

    fn is_request_from_trusted_source(
        &self,
        request: &ContinueLoginRequestDTO,
        user_result: &UserAuthentication,
    ) -> bool {
        request.user_agent == user_result.otp.user_agent
            && request.ip_address == user_result.otp.ip_address
    }

    async fn verify_email_otp(
        &self,
        user: &UserAuthentication,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        // Implement actual verification logic here
        todo!()
    }

    async fn verify_authenticator_app(
        &self,
        user: &UserAuthentication,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        // Implement actual verification logic here
        todo!()
    }

    async fn create_session_for_user(
        &self,
        user: &UserAuthentication,
        persistent: bool,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let session_id = Uuid::new_v4().to_string();
        let session_name = Self::generate_session_name();
        let user_id = FindUserByIdDTO::new(&user.user_id);

        let expiry = Utc::now()
            + if persistent {
                Duration::days(14)
            } else {
                Duration::days(2)
            };

        let session = UserSession::new(
            &user.user_id,
            &session_id,
            &session_name,
            Utc::now(),
            &user_agent,
            &ip_address,
            expiry,
        );

        self.user_authentication_repository
            .save_user_session(&session)
            .await?;

        self.user_authentication_repository
            .update_user_login_attempts(user_id, 0)
            .await?;

        Ok(AuthenticationOutcome::AuthenticatedWithPreferences {
            session,
            email: user.email.clone(),
            message: "Login successful.".to_string(),
            email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
        })
    }
}
