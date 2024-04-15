use crate::core::constants::emojis::EMOJIS;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::{UserAuthentication, VerificationInfo};
use crate::domain::entities::user::user_sessions::UserSession;

use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::repositories::user::user_authentication_parameters::CreateLoginRequestDTO;
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
        self.process_login_attempt(&user_result, &request.password, &request)
            .await
    }

    pub async fn continue_login(
        &self,
        user_id: String,
        verification_info: VerificationInfo,
    ) -> Result<AuthenticationOutcome, DomainError> {
        // 1. Retrieve the user's ongoing authentication flow state (possibly from a cache).
        // 2. Verify any provided 2FA codes or other verification details.
        // 3. Update the authentication flow state as necessary.
        // 4. Invalid attempts count
        // Return either a success token or prompt for further action as needed.
        todo!()
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
        password: &str,
        request: &CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        UserValidationService::validate_password(password)?;

        if !UserCredentialService::credential_validator(&user.pass_hash, password)? {
            self.handle_failed_login_attempt(user).await
        } else {
            self.handle_successful_login_attempt(user, request).await
        }
    }

    async fn handle_failed_login_attempt(
        &self,
        user: &UserAuthentication,
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
            message: "Incorrect password.".to_string(),
            email_notifications_enabled: user.security_setting.email_on_failure_enabled_at,
        })
    }

    async fn handle_successful_login_attempt(
        &self,
        user: &UserAuthentication,
        request: &CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        match (
            user.security_setting.two_factor_email,
            user.security_setting.two_factor_authenticator_app,
        ) {
            (true, true) => {
                // Both two-factor authentication methods are enabled
                // Handle case where both email and authenticator app verification are required
                let duration = Duration::minutes(5);
                let confirmation_token = self
                    .generate_and_prepare_token(&user.user_id, duration)
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
                let duration = Duration::minutes(5);
                let confirmation_token = self
                    .generate_and_prepare_token(&user.user_id, duration)
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
                let token = None;
                let expiry_duration = Duration::minutes(3);
                self.prepare_2fa(user_id, token, expiry_duration).await?;

                Ok(AuthenticationOutcome::RequireAuthenticatorApp {
                    user_id: user.user_id.clone(),
                    email: user.email.clone(),
                    email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
                })
            }
            (false, false) => self.create_session_for_user(user, request).await,
        }
    }

    async fn prepare_2fa(
        &self,
        user_id: FindUserByIdDTO,
        email_token_hash: Option<String>,
        expiry_duration: Duration,
    ) -> Result<(), DomainError> {
        let expiry = Utc::now() + expiry_duration;
        self.user_authentication_repository
            .prepare_user_for_2fa(user_id, expiry, email_token_hash)
            .await
    }

    async fn generate_and_prepare_token(
        &self,
        user_id: &str,
        duration: Duration,
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
            )
            .await?;

        Ok(confirmation_token)
    }

    async fn create_session_for_user(
        &self,
        user: &UserAuthentication,
        request: &CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let session_id = Uuid::new_v4().to_string();
        let session_name = Self::generate_session_name();
        let user_id = FindUserByIdDTO::new(&user.user_id);

        let expiry = Utc::now()
            + if request.persistent {
                Duration::days(14)
            } else {
                Duration::days(2)
            };

        let session = UserSession::new(
            &user.user_id,
            &session_id,
            &session_name,
            Utc::now(),
            &request.ip_address,
            &request.user_agent,
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
