use crate::core::constants::emojis::EMOJIS;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_authentication::VerificationInfo;
use crate::domain::entities::user::user_sessions::UserSession;

use crate::domain::entities::user::AuthenticationOutcome;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_authentication_parameters::CreateLoginRequestDTO;
use crate::domain::repositories::user::user_authentication_repository::UserAuthenticationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByUsernameDTO,
};
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
        let identifier_str = &request.identifier;

        let user_result = if EMAIL_REGEX.is_match(identifier_str) {
            UserValidationService::validate_email(&Email::new(identifier_str))?;
            self.user_authentication_repository
                .get_user_by_email(FindUserByEmailDTO {
                    email: Email::new(identifier_str),
                })
                .await
        } else {
            UserValidationService::validate_username(&Username::new(identifier_str))?;
            self.user_authentication_repository
                .get_user_by_username(FindUserByUsernameDTO {
                    username: Username::new(identifier_str),
                })
                .await
        };

        UserValidationService::validate_password(&request.password)?;

        match user_result {
            Ok(user) => {
                let credential_check =
                    UserCredentialService::credential_validator(&user.pass_hash, &request.password);
                match credential_check {
                    Ok(true) => {
                        let outcome = match (
                            user.security_setting.two_factor_email,
                            user.security_setting.two_factor_authenticator_app,
                        ) {
                            (true, true) => {
                                // Both two-factor authentication methods are enabled
                                // Handle case where both email and authenticator app verification are required

                                // save email code to db

                                todo!()
                            }
                            (true, false) => {
                                // Only two-factor email authentication is enabled
                                // Handle case where only email verification is required

                                // save email code to db

                                todo!()
                            }
                            (false, true) => {
                                // Only two-factor authenticator app authentication is enabled
                                // Handle case where only authenticator app verification is required
                                todo!()
                            }
                            (false, false) => {
                                // No two-factor authentication is enabled
                                // Proceed with session saving logic or further actions since no additional verification is needed
                                let session_id = Uuid::new_v4().to_string();
                                let login_timestamp = Utc::now();
                                let expiry_duration = if request.persistent {
                                    Duration::days(7)
                                } else {
                                    Duration::days(1)
                                };
                                let expiry = login_timestamp + expiry_duration;

                                let session_name = Self::generate_session_name();
                                let session = UserSession {
                                    user_id: user.user_id,
                                    session_id,
                                    session_name,
                                    login_timestamp,
                                    ip_address: request.ip_address,
                                    user_agent: request.user_agent,
                                    expiry,
                                };

                                // Save the session
                                self.user_authentication_repository
                                    .save_user_session(session.clone())
                                    .await?;

                                AuthenticationOutcome::AuthenticatedWithPreferences {
                                    session,
                                    email: user.email,
                                    message: "Login successful.".to_string(),
                                    email_notifications_enabled: user
                                        .security_setting
                                        .email_on_success_enabled_at,
                                }
                            }
                        };
                        Ok(outcome)
                    }
                    Ok(false) => Ok(AuthenticationOutcome::AuthenticationFailed {
                        email: user.email,
                        message: "Incorrect password.".to_string(),
                        email_notifications_enabled: user
                            .security_setting
                            .email_on_failure_enabled_at,
                    }),
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn continue_login(
        &self,
        user_id: String,
        verification_info: VerificationInfo,
    ) -> Result<AuthenticationOutcome, DomainError> {
        // 1. Retrieve the user's ongoing authentication flow state (possibly from a cache).
        // 2. Verify any provided 2FA codes or other verification details.
        // 3. Update the authentication flow state as necessary.
        // Return either a success token or prompt for further action as needed.
        todo!()
    }
    fn generate_session_name() -> String {
        use rand::seq::SliceRandom;
        let mut rng = &mut rand::thread_rng();
        EMOJIS
            .choose_multiple(&mut rng, 5)
            .cloned()
            .collect::<String>()
            .to_string()
    }
}
