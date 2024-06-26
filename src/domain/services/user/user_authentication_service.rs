use crate::core::constants::emojis::EMOJIS;
use crate::domain::entities::shared::value_objects::{IPAddress, OtpToken, UserAgent};
use crate::domain::entities::shared::value_objects::{OtpCode, UserId};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::{
    UserAuthentication, UserAuthenticationData,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::ports::repositories::user::user_authentication_dto::{
    ContinueLoginRequestDTO, CreateLoginRequestDTO, DomainVerificationMethod,
};
use crate::domain::ports::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;

use crate::domain::ports::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::user_validation_service::EMAIL_REGEX;
use crate::domain::services::user::{UserCredentialService, UserValidationService};
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

pub struct UserAuthenticationDomainService<A, R>
where
    A: UserAuthenticationDomainRepository,
    R: UserRegistrationDomainRepository,
{
    auth_repo: A,
    reg_repo: Arc<R>,
}

impl<A, R> UserAuthenticationDomainService<A, R>
where
    A: UserAuthenticationDomainRepository,
    R: UserRegistrationDomainRepository,
{
    pub fn new(auth_repo: A, reg_repo: Arc<R>) -> Self {
        Self {
            auth_repo,
            reg_repo,
        }
    }
    pub async fn initiate_login(
        &self,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let identifier = &request.identifier;
        let user_result = self.identify_user(identifier).await?;

        if !user_result.user_credentials.email_validated {
            return self.process_unvalidated_email(user_result).await;
        }

        UserValidationService::validate_blocked_time(
            user_result.auth_data.login_blocked_until,
            "Your account is locked until",
        )?;
        self.process_login_attempt(&user_result, request).await
    }

    pub async fn continue_login(
        &self,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let auth_result = self
            .auth_repo
            .get_user_auth_by_token(request.public_token.clone())
            .await?;

        UserValidationService::validate_blocked_time(
            auth_result.auth_data.login_blocked_until,
            "Your account is locked until",
        )?;

        if !self.is_request_from_trusted_source(&request, &auth_result.auth_data) {
            let message = "IP address or user agent mismatch.";
            return self
                .process_failed_login_attempt(&auth_result, message)
                .await;
        }
        self.verify_otp(&auth_result, request).await
    }
}

impl<A, R> UserAuthenticationDomainService<A, R>
where
    A: UserAuthenticationDomainRepository,
    R: UserRegistrationDomainRepository,
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
            self.auth_repo.get_user_by_email(email).await
        } else {
            let username = Username::new(identifier);
            UserValidationService::validate_username(&username)?;
            self.auth_repo.get_user_by_username(&username).await
        }
    }

    async fn process_login_attempt(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        UserValidationService::validate_passwd(&request.password)?;

        if UserCredentialService::credential_validator(
            &request.password,
            &user.user_credentials.pass_hash,
        )? {
            self.process_successful_login_attempt(user, request).await
        } else {
            let message = "Incorrect password.";
            self.process_failed_login_attempt(&user, message).await
        }
    }

    async fn process_failed_login_attempt(
        &self,
        user: &UserAuthentication,
        message: &str,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let attempt_count: i64 = user.auth_data.attempt_count + 1;
        let block_duration = Self::calculate_block_duration(attempt_count);
        let update_attempts = self
            .auth_repo
            .update_user_login_attempts(&user.user_id, attempt_count);
        let block_user = self
            .auth_repo
            .block_user_until(&user.user_id, block_duration);

        tokio::try_join!(update_attempts, block_user)?;

        Ok(AuthenticationOutcome::AuthenticationFailed {
            email: user.email.clone(),
            message: message.to_string(),
            email_notifications_enabled: user.security_setting.email_on_failure_enabled_at,
        })
    }

    async fn process_successful_login_attempt(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let two_factor = (
            user.security_setting.two_factor_email,
            user.security_setting.two_factor_authenticator_app,
        );

        match two_factor {
            (true, true) => self.process_both_two_factor(user, request).await,
            (true, false) => self.process_email_two_factor(user, request).await,
            (false, true) => self.process_app_two_factor(user, request).await,
            (false, false) => {
                self.create_session(
                    user,
                    request.persistent,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
        }
    }

    fn calculate_block_duration(attempt_count: i64) -> Option<chrono::DateTime<Utc>> {
        if attempt_count > 10 {
            Some(Utc::now() + Duration::hours(3))
        } else if attempt_count > 5 {
            Some(Utc::now() + Duration::minutes(15))
        } else {
            None
        }
    }
    fn prepare_two_factor_data(
        &self,
    ) -> Result<(OtpToken, OtpCode, String, chrono::DateTime<Utc>), DomainError> {
        let otp_token_str = SharedDomainService::generate_token(64)?;
        let otp_token = OtpToken::new(&otp_token_str);
        let otp_code_str = SharedDomainService::generate_token(32)?;
        let otp_code = OtpCode::new(&otp_code_str);
        let otp_code_hash = SharedDomainService::hash_token(&otp_code_str);
        let duration = Utc::now() + Duration::minutes(10);
        Ok((otp_token, otp_code, otp_code_hash, duration))
    }

    async fn process_both_two_factor(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let (otp_token, otp_code, otp_code_hash, duration) = self.prepare_two_factor_data()?;
        self.auth_repo
            .prepare_user_for_2fa(
                &user.user_id,
                otp_token.clone(),
                Some(otp_code_hash),
                duration,
                request.user_agent,
                request.ip_address,
                request.persistent,
            )
            .await?;

        Ok(AuthenticationOutcome::RequireEmailAndAuthenticatorApp {
            otp_token,
            otp_code,
            email: user.email.clone(),
        })
    }

    async fn process_email_two_factor(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let (otp_token, otp_code, otp_code_hash, duration) = self.prepare_two_factor_data()?;
        self.auth_repo
            .prepare_user_for_2fa(
                &user.user_id,
                otp_token.clone(),
                Some(otp_code_hash),
                duration,
                request.user_agent,
                request.ip_address,
                request.persistent,
            )
            .await?;

        Ok(AuthenticationOutcome::RequireEmailVerification {
            otp_token,
            otp_code,
            email: user.email.clone(),
        })
    }

    async fn process_app_two_factor(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let (otp_token, _, _, duration) = self.prepare_two_factor_data()?;
        self.auth_repo
            .prepare_user_for_2fa(
                &user.user_id,
                otp_token.clone(),
                None,
                duration,
                request.user_agent,
                request.ip_address,
                request.persistent,
            )
            .await?;

        Ok(AuthenticationOutcome::RequireAuthenticatorApp {
            otp_token,
            email: user.email.clone(),
            email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
        })
    }

    fn is_request_from_trusted_source(
        &self,
        request: &ContinueLoginRequestDTO,
        user_result: &UserAuthenticationData,
    ) -> bool {
        UserValidationService::validate_ip_ua(
            &request.user_agent,
            &request.ip_address,
            user_result.user_agent.as_ref(),
            user_result.ip_address.as_ref(),
        )
    }

    async fn verify_otp(
        &self,
        auth_result: &UserAuthentication,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let current_time = Utc::now();

        // Check if the OTP expiry is set and validate against current time
        if let Some(expiry) = auth_result.auth_data.expiry {
            if current_time > expiry {
                // Return an error if the OTP has expired
                return Err(DomainError::ValidationError(
                    ValidationError::BusinessRuleViolation(
                        "The OTP has expired. Please restart the login process.".to_string(),
                    ),
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
            DomainVerificationMethod::EmailOTP => {
                self.verify_email_otp(auth_result, &request.otp_code.value())
            }
            DomainVerificationMethod::AuthenticatorApp => self.verify_authenticator_app(
                auth_result.user_credentials.totp_secret.clone(),
                &request.otp_code.value(),
            )?,
        };

        // Handle the result of the OTP verification
        match verification_result {
            true => {
                self.update_verification_status(&auth_result.user_id, &request.verification_method)
                    .await?;
                self.process_verification_status(&auth_result, request)
                    .await
            }
            false => {
                let message = "Verification failed due to invalid OTP.";
                self.process_failed_login_attempt(auth_result, message)
                    .await
            }
        }
    }

    fn verify_email_otp(&self, user: &UserAuthentication, code: &str) -> bool {
        let token_hash = SharedDomainService::hash_token(code);
        if let Some(token) = &user.auth_data.otp_email_code_hash {
            token.value() == &token_hash
        } else {
            false
        }
    }

    fn verify_authenticator_app(
        &self,
        totp_secret: Option<String>,
        code: &str,
    ) -> Result<bool, DomainError> {
        let secret = totp_secret.ok_or_else(|| {
            DomainError::ValidationError(ValidationError::BusinessRuleViolation(
                "Missing totp secret".to_string(),
            ))
        })?;

        match UserValidationService::verify_totp(&secret, code) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn update_verification_status(
        &self,
        user_id: &UserId,
        verification_method: &DomainVerificationMethod,
    ) -> Result<(), DomainError> {
        match verification_method {
            DomainVerificationMethod::EmailOTP => {
                self.auth_repo.set_email_otp_verified(user_id).await
            }
            DomainVerificationMethod::AuthenticatorApp => {
                self.auth_repo.set_app_otp_verified(user_id).await
            }
        }
    }

    async fn process_verification_status(
        &self,
        user: &UserAuthentication,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let user_updated = self.auth_repo.get_user_by_username(&user.username).await?;
        // Determine if further verification is needed
        let email_needed = user_updated.security_setting.two_factor_email;
        let app_needed = user_updated.security_setting.two_factor_authenticator_app;
        let email_done = user_updated.auth_data.otp_email_currently_valid;
        let app_done = user_updated.auth_data.otp_app_currently_valid;

        match (email_needed, app_needed, email_done, app_done) {
            (true, true, true, true) => {
                // Both methods are verified
                self.create_session(
                    user,
                    user.auth_data.long_session,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
            (true, true, false, true) => {
                // Email verification remains
                Ok(AuthenticationOutcome::PendingVerification {
                    message: "Please verify your email auth code to complete login.".to_string(),
                })
            }
            (true, true, true, false) => {
                // App verification remains
                Ok(AuthenticationOutcome::PendingVerification {
                    message: "Please verify using your authenticator app to complete login."
                        .to_string(),
                })
            }
            (true, false, true, _) => {
                // Only email is needed and done
                self.create_session(
                    user,
                    user.auth_data.long_session,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
            (false, true, _, true) => {
                // Only app is needed and done
                self.create_session(
                    user,
                    user.auth_data.long_session,
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
                    message: "Additional verification required to complete login.".to_string(),
                })
            }
        }
    }

    async fn create_session(
        &self,
        user: &UserAuthentication,
        long_session: bool,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let session_id = Uuid::new_v4().to_string();
        let session_name = Self::generate_session_name();
        let expiry = Utc::now()
            + if long_session {
                Duration::days(14)
            } else {
                Duration::days(2)
            };

        let session = UserSession::new(
            &user.user_id.user_id,
            &session_id,
            &session_name,
            Utc::now(),
            &user_agent,
            &ip_address,
            expiry,
            true,
        );

        let save_session = self.auth_repo.save_user_session(&session);
        let reset_attempts = self.auth_repo.update_user_login_attempts(&user.user_id, 0);
        let reset_validity = self.auth_repo.reset_otp_validity(&user.user_id);

        tokio::try_join!(save_session, reset_attempts, reset_validity)?;
        Ok(AuthenticationOutcome::AuthenticatedWithPreferences {
            session,
            email: user.email.clone(),
            message: "Login successful.".to_string(),
            email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
        })
    }

    async fn process_unvalidated_email(
        &self,
        user_result: UserAuthentication,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let now = Utc::now();
        let confirmation = self
            .reg_repo
            .get_primary_email_activation(&user_result.user_id)
            .await?;

        if now > confirmation.expiry {
            self.generate_new_confirmation_token(user_result.user_id, user_result.email)
                .await
        } else {
            Err(DomainError::ValidationError(
                ValidationError::BusinessRuleViolation(
                    "Your account email is not validated yet!".to_string(),
                ),
            ))
        }
    }

    async fn generate_new_confirmation_token(
        &self,
        user_id: UserId,
        email: Email,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let token = SharedDomainService::generate_token(64)?;
        let confirmation_token = OtpToken::new(&token);
        let confirmation_token_hash = SharedDomainService::hash_token(&token);
        let expiry = Utc::now() + Duration::days(1);

        self.reg_repo
            .store_main_primary_activation_token(user_id.clone(), confirmation_token_hash, expiry)
            .await?;

        Ok(AuthenticationOutcome::UserEmailConfirmation {
            email,
            token: confirmation_token,
        })
    }
}
