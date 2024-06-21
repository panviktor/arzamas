use crate::core::constants::emojis::EMOJIS;
use crate::domain::entities::shared::value_objects::{IPAddress, OtpToken, UserAgent};
use crate::domain::entities::shared::value_objects::{OtpCode, UserId};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::ports::repositories::user::user_authentication_dto::{
    ContinueLoginRequestDTO, CreateLoginRequestDTO, DomainVerificationMethod,
};
use crate::domain::ports::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;

use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::user_validation_service::EMAIL_REGEX;
use crate::domain::services::user::{UserCredentialService, UserValidationService};
use actix_web::web::to;
use chrono::{Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

pub struct UserAuthenticationDomainService<A, S>
where
    A: UserAuthenticationDomainRepository,
    S: UserSharedDomainRepository,
{
    user_authentication_repository: A,
    user_repository: Arc<S>,
}

impl<A, S> UserAuthenticationDomainService<A, S>
where
    A: UserAuthenticationDomainRepository,
    S: UserSharedDomainRepository,
{
    pub fn new(user_authentication_repository: A, user_repository: Arc<S>) -> Self {
        Self {
            user_authentication_repository,
            user_repository,
        }
    }
    pub async fn initiate_login(
        &self,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let identifier = &request.identifier;
        let user_result = self.identify_user(identifier).await?;

        if !user_result.email_validated {
            return self.handle_unvalidated_email(user_result).await;
        }

        UserValidationService::validate_blocked_time(
            user_result.login_blocked_until,
            "Your account is locked until",
        )?;
        self.process_login_attempt(&user_result, request).await
    }

    pub async fn continue_login(
        &self,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        //  request.otp_token - find user by token

        // let identifier = &request.identifier;
        // let user_result = self.identify_user(identifier).await?;
        // UserValidationService::validate_blocked_time(
        //     user_result.login_blocked_until,
        //     "Your account is locked until",
        // )?;
        // if !self.is_request_from_trusted_source(&request, &user_result) {
        //     let message = "IP address or user agent mismatch.";
        //     return self
        //         .handle_failed_login_attempt(&user_result, message)
        //         .await;
        // }
        // self.verify_otp(&user_result, request).await

        todo!()
    }
}

impl<R, U> UserAuthenticationDomainService<R, U>
where
    R: UserAuthenticationDomainRepository,
    U: UserSharedDomainRepository,
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
            self.user_authentication_repository
                .get_user_by_email(email)
                .await
        } else {
            let username = Username::new(identifier);
            UserValidationService::validate_username(&username)?;
            self.user_authentication_repository
                .get_user_by_username(&username)
                .await
        }
    }

    async fn process_login_attempt(
        &self,
        user: &UserAuthentication,
        request: CreateLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        UserValidationService::validate_passwd(&request.password)?;

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
        let attempt_count: i64 = user.auth_data.attempt_count + 1;
        let user_id = UserId::new(&user.user_id);

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
        // match (
        //     user.security_setting.two_factor_email,
        //     user.security_setting.two_factor_authenticator_app,
        // ) {
        //     (true, true) => {
        //         // Both two-factor authentication methods are enabled
        //         // Handle case
        //         // where both email and authenticator app verification is required
        //         let duration = Duration::minutes(10);
        //         let confirmation_token = self
        //             .generate_and_prepare_token(
        //                 &user.user_id,
        //                 duration,
        //                 request.user_agent,
        //                 request.ip_address,
        //                 request.persistent,
        //             )
        //             .await?;
        //         Ok(AuthenticationOutcome::RequireEmailAndAuthenticatorApp {
        //             user_id: user.user_id.clone(),
        //             email: user.email.clone(),
        //             token: confirmation_token,
        //         })
        //     }
        //     (true, false) => {
        //         // Only two-factor email authentication is enabled
        //         // Handle case where only email verification is required
        //         let duration = Duration::minutes(10);
        //         let confirmation_token = self
        //             .generate_and_prepare_token(
        //                 &user.user_id,
        //                 duration,
        //                 request.user_agent,
        //                 request.ip_address,
        //                 request.persistent,
        //             )
        //             .await?;
        //         Ok(AuthenticationOutcome::RequireEmailVerification {
        //             user_id: user.user_id.clone(),
        //             email: user.email.clone(),
        //             token: confirmation_token,
        //         })
        //     }
        //     (false, true) => {
        //         // Only two-factor authenticator app authentication is enabled
        //         // Handle case where only authenticator app verification is required
        //         let user_id = UserId::new(&user.user_id);
        //         let expiry_duration = Duration::minutes(5);
        //         self.prepare_2fa(
        //             user_id,
        //             expiry_duration,
        //             request.user_agent,
        //             request.ip_address,
        //             request.persistent,
        //         )
        //         .await?;
        //
        //         Ok(AuthenticationOutcome::RequireAuthenticatorApp {
        //             user_id: user.user_id.clone(),
        //             email: user.email.clone(),
        //             email_notifications_enabled: user.security_setting.email_on_success_enabled_at,
        //         })
        //     }
        //     (false, false) => {
        //         self.create_session_for_user(
        //             user,
        //             request.persistent,
        //             request.user_agent,
        //             request.ip_address,
        //         )
        //         .await
        //     }
        // }

        todo!()
    }

    async fn generate_and_prepare_token(
        &self,
        user_id: &str,
        duration: Duration,
        user_agent: UserAgent,
        ip_address: IPAddress,
        persistent: bool,
    ) -> Result<OtpCode, DomainError> {
        let user_id_dto = UserId::new(user_id);

        // Generating token for public use
        let otp_token_str = SharedDomainService::generate_token(64)?;
        let otp_token = OtpToken::new(&otp_token_str);

        // Generating code for email sending
        let otp_code_str = SharedDomainService::generate_token(16)?;
        let otp_code = OtpCode::new(&otp_code_str);
        let otp_code_hash = SharedDomainService::hash_token(&otp_code_str);

        // Setting code valid duration
        let code_valid_duration = Utc::now() + duration;

        // self.user_authentication_repository
        //     .prepare_user_for_2fa(
        //         user_id_dto,
        //         otp_token,
        //         otp_code_hash,
        //         code_valid_duration,
        //         user_agent,
        //         ip_address,
        //         persistent,
        //     )
        //     .await?;

        todo!()

        // Ok(otp_code)
    }

    fn is_request_from_trusted_source(
        &self,
        request: &ContinueLoginRequestDTO,
        user_result: &UserAuthentication,
    ) -> bool {
        UserValidationService::validate_ip_ua(
            &request.user_agent,
            &request.ip_address,
            user_result.auth_data.user_agent.as_ref(),
            user_result.auth_data.ip_address.as_ref(),
        )
    }

    async fn verify_otp(
        &self,
        user_result: &UserAuthentication,
        request: ContinueLoginRequestDTO,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let current_time = Utc::now();

        // // Check if the OTP expiry is set and validate against current time
        // if let Some(expiry) = user_result.otp.expiry {
        //     if current_time > expiry {
        //         // Return an error if the OTP has expired
        //         return Err(DomainError::ValidationError(
        //             ValidationError::BusinessRuleViolation("OTP has expired.".to_string()),
        //         ));
        //     }
        // } else {
        //     // Return an error if no expiry is set (critical configuration error)
        //     return Err(DomainError::ValidationError(
        //         ValidationError::BusinessRuleViolation("Expiry must be set.".to_string()),
        //     ));
        // }
        //
        // // Determine the verification result based on the method specified in the request
        // let verification_result = match &request.verification_method {
        //     DomainVerificationMethod::EmailOTP => self.verify_email_otp(user_result, &request.code),
        //     DomainVerificationMethod::AuthenticatorApp => {
        //         self.verify_authenticator_app(user_result, &request.code)?
        //     }
        // };
        //
        // // Handle the result of the OTP verification
        // match verification_result {
        //     true => {
        //         let user_id = UserId::new(&user_result.user_id);
        //         self.update_verification_status(user_id, &request.verification_method)
        //             .await?;
        //         self.handle_verification_status(&user_result, request).await
        //     }
        //     false => {
        //         let message = "Verification failed due to invalid OTP.";
        //         self.handle_failed_login_attempt(user_result, message).await
        //     }
        // }

        todo!()
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
        user_id: UserId,
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
        let user_updated = self
            .user_authentication_repository
            .get_user_by_username(&user.username)
            .await?;

        // Determine if further verification is needed
        let email_needed = user_updated.security_setting.two_factor_email;
        let app_needed = user_updated.security_setting.two_factor_authenticator_app;
        let email_done = user_updated.auth_data.otp_email_currently_valid;
        let app_done = user_updated.auth_data.otp_app_currently_valid;

        match (email_needed, app_needed, email_done, app_done) {
            (true, true, true, true) => {
                // Both methods are verified
                self.create_session_for_user(
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
                    message: "Please verify your email to complete login.".to_string(),
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
                self.create_session_for_user(
                    user,
                    user.auth_data.long_session,
                    request.user_agent,
                    request.ip_address,
                )
                .await
            }
            (false, true, _, true) => {
                // Only app is needed and done
                self.create_session_for_user(
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

    async fn create_session_for_user(
        &self,
        user: &UserAuthentication,
        persistent: bool,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let session_id = Uuid::new_v4().to_string();
        let session_name = Self::generate_session_name();
        let user_id = UserId::new(&user.user_id);

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
            true,
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

    async fn handle_unvalidated_email(
        &self,
        user_result: UserAuthentication,
    ) -> Result<AuthenticationOutcome, DomainError> {
        let user_id = UserId::new(&user_result.user_id);
        let now = Utc::now();
        let confirmation = self
            .user_repository
            .retrieve_email_confirmation_token(&user_id)
            .await?;

        if now > confirmation.expiry {
            self.generate_new_confirmation_token(user_id, user_result.email)
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

        self.user_repository
            .store_email_confirmation_token(user_id.clone(), confirmation_token_hash, expiry, None)
            .await?;

        Ok(AuthenticationOutcome::UserEmailConfirmation {
            email,
            token: confirmation_token,
        })
    }
}
