use crate::core::constants::emojis::EMOJIS;
use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::ports::repositories::user::user_authentication_parameters::{
    ContinueLoginRequestDTO, CreateLoginRequestDTO, DomainVerificationMethod,
};
use crate::domain::ports::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::{
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

        self.check_email_validated(&user_result)?;
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
        if !self.is_request_from_trusted_source(&request, &user_result) {
            let message = "IP address or user agent mismatch.";
            return self
                .handle_failed_login_attempt(&user_result, message)
                .await;
        }
        self.verify_otp(&user_result, request).await
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
            let email = Email::new(identifier);
            UserValidationService::validate_email(&email)?;
            let email_dto = FindUserByEmailDTO::new(email);
            self.user_authentication_repository
                .get_user_by_email(email_dto)
                .await
        } else {
            let username = Username::new(identifier);
            UserValidationService::validate_username(&username)?;
            let username_dto = FindUserByUsernameDTO::new(&username);
            self.user_authentication_repository
                .get_user_by_username(username_dto)
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

    fn check_email_validated(&self, user_result: &UserAuthentication) -> Result<(), DomainError> {
        if !user_result.email_validated {
            return Err(DomainError::ValidationError(
                ValidationError::BusinessRuleViolation(
                    "Your account email not validated yet!".to_string(),
                ),
            ));
        }
        Ok(())
    }

    async fn process_login_attempt(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        UserValidationService::validate_password(&request.password)?;

        if !UserCredentialService::credential_validator(&request.password, &user.pass_hash)? {
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
        let attempt_count = user.otp.attempt_count + 1;
        let user_id = FindUserByIdDTO::new(&user.user_id);

        let block_duration = if attempt_count > 10 {
            Some(Utc::now() + Duration::hours(3))
        } else if attempt_count > 5 {
            Some(Utc::now() + Duration::minutes(15))
        } else {
            None
        };

        let update_user_login_attempts = self
            .user_authentication_repository
            .update_user_login_attempts(user_id.clone(), attempt_count);

        let block_user_until = self
            .user_authentication_repository
            .block_user_until(&user_id, block_duration);

        tokio::try_join!(update_user_login_attempts, block_user_until)?;

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
                        request.persistent,
                    )
                    .await?;
                Ok(AuthenticationOutcome::RequireEmailAndAuthenticatorApp {
                    user_id: user.user_id.clone(),
                    email: user.email.clone(),
                    token: confirmation_token,
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
                        request.persistent,
                    )
                    .await?;
                Ok(AuthenticationOutcome::RequireEmailVerification {
                    user_id: user.user_id.clone(),
                    email: user.email.clone(),
                    token: confirmation_token,
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
                    request.persistent,
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
        persistent: bool,
    ) -> Result<(), DomainError> {
        let expiry = Utc::now() + expiry_duration;
        self.user_authentication_repository
            .prepare_user_for_2fa(user_id, expiry, None, user_agent, ip_address, persistent)
            .await
    }

    async fn generate_and_prepare_token(
        &self,
        user_id: &str,
        duration: Duration,
        user_agent: UserAgent,
        ip_address: IPAddress,
        persistent: bool,
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
                persistent,
            )
            .await?;

        Ok(confirmation_token)
    }

    fn is_request_from_trusted_source(
        &self,
        request: &ContinueLoginRequestDTO,
        user_result: &UserAuthentication,
    ) -> bool {
        let user_agent = match &user_result.otp.user_agent {
            Some(ua) => ua,
            None => return false,
        };

        let ip_address = match &user_result.otp.ip_address {
            Some(ip) => ip,
            None => return false,
        };

        &request.user_agent == user_agent && &request.ip_address == ip_address
    }

    async fn verify_otp(
        &self,
        user_result: &UserAuthentication,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let current_time = Utc::now();

        // Check if the OTP expiry is set and validate against current time
        if let Some(expiry) = user_result.otp.expiry {
            if current_time > expiry {
                // Return an error if the OTP has expired
                return Err(DomainError::ValidationError(
                    ValidationError::BusinessRuleViolation("OTP has expired.".to_string()),
                ));
            }
        } else {
            // Return an error if no expiry is set (critical configuration error)
            return Err(DomainError::ValidationError(
                ValidationError::BusinessRuleViolation("Expiry must be set.".to_string()),
            ));
        }

        // Determine the verification result based on the method specified in the request
        let verification_result = match &request.verification_method {
            DomainVerificationMethod::EmailOTP => self.verify_email_otp(user_result, &request.code),
            DomainVerificationMethod::AuthenticatorApp => {
                self.verify_authenticator_app(user_result, &request.code)?
            }
        };

        // Handle the result of the OTP verification
        match verification_result {
            true => {
                let user_id = FindUserByIdDTO::new(&user_result.user_id);
                self.update_verification_status(user_id, &request.verification_method)
                    .await?;
                self.handle_verification_status(&user_result, request).await
            }
            false => {
                let message = "Verification failed due to invalid OTP.";
                self.handle_failed_login_attempt(user_result, message).await
            }
        }
    }

    fn verify_email_otp(&self, user: &UserAuthentication, code: &str) -> bool {
        let token_hash = SharedDomainService::hash_token(code);
        if let Some(token) = &user.otp.otp_email_hash {
            token == &token_hash
        } else {
            false
        }
    }

    fn verify_authenticator_app(
        &self,
        user: &UserAuthentication,
        code: &str,
    ) -> Result<bool, DomainError> {
        // let secret = "secret".to_string().into_bytes();
        // let code = "code";
        //
        // let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret).map_err(|e| {
        //     e.to_string();
        //     DomainError::ExternalServiceError(ExternalServiceError::Custom(format!(
        //         "Failed to create TOTP: {}",
        //         e
        //     )))
        // });
        //
        // let res = totp.expect("REASON").check_current(code);
        // if res {
        //     true
        // } else {
        //     false
        // }

        todo!()
    }

    async fn update_verification_status(
        &self,
        user_id: FindUserByIdDTO,
        verification_method: &DomainVerificationMethod,
    ) -> Result<(), DomainError> {
        match verification_method {
            DomainVerificationMethod::EmailOTP => {
                self.user_authentication_repository
                    .set_email_otp_verified(user_id)
                    .await
            }
            DomainVerificationMethod::AuthenticatorApp => {
                self.user_authentication_repository
                    .set_app_otp_verified(user_id)
                    .await
            }
        }
    }

    async fn handle_verification_status(
        &self,
        user: &UserAuthentication,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let username = FindUserByUsernameDTO::new(&user.username);

        let user_updated = self
            .user_authentication_repository
            .get_user_by_username(username)
            .await?;

        // Determine if further verification is needed
        let email_needed = user_updated.security_setting.two_factor_email;
        let app_needed = user_updated.security_setting.two_factor_authenticator_app;
        let email_done = user_updated.otp.otp_email_currently_valid;
        let app_done = user_updated.otp.otp_app_currently_valid;

        match (email_needed, app_needed, email_done, app_done) {
            (true, true, true, true) => {
                // Both methods are verified
                self.create_session_for_user(
                    user,
                    user.otp.persistent,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
            (true, true, false, true) => {
                // Email verification remains
                Ok(AuthenticationOutcome::PendingVerification {
                    user_id: user_updated.user_id,
                    message: "Please verify your email to complete login.".to_string(),
                })
            }
            (true, true, true, false) => {
                // App verification remains
                Ok(AuthenticationOutcome::PendingVerification {
                    user_id: user_updated.user_id,
                    message: "Please verify using your authenticator app to complete login."
                        .to_string(),
                })
            }
            (true, false, true, _) => {
                // Only email is needed and done
                self.create_session_for_user(
                    user,
                    user.otp.persistent,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
            (false, true, _, true) => {
                // Only app is needed and done
                self.create_session_for_user(
                    user,
                    user.otp.persistent,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
            (false, false, _, _) => Err(DomainError::ValidationError(
                ValidationError::BusinessRuleViolation(
                    "Two-factor authentication is not enabled on your account.".to_string(),
                ),
            )),
            _ => {
                // Catch-all for any other combinations, typically should not occur
                Ok(AuthenticationOutcome::PendingVerification {
                    user_id: user_updated.user_id,
                    message: "Additional verification required to complete login.".to_string(),
                })
            }
        }
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

        let save_session = self
            .user_authentication_repository
            .save_user_session(&session);
        let reset_attempts = self
            .user_authentication_repository
            .update_user_login_attempts(user_id.clone(), 0);
        let reset_validity = self
            .user_authentication_repository
            .reset_otp_validity(user_id);

        tokio::try_join!(save_session, reset_attempts, reset_validity)?;

        Ok(AuthenticationOutcome::AuthenticatedWithPreferences {
            session,
            email: user.email.clone(),
            message: "Login successful.".to_string(),
            email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
        })
    }
}
