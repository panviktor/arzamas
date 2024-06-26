use crate::domain::entities::shared::value_objects::OtpToken;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::ports::repositories::user::user_recovery_password_dto::{
    RecoveryPasswdRequestDTO, RecoveryPasswdResponse, UserCompleteRecoveryRequestDTO,
    UserRecoveryPasswdOutcome,
};
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;

use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::user_validation_service::EMAIL_REGEX;
use crate::domain::services::user::{UserCredentialService, UserValidationService};
use chrono::{Duration, Utc};
use std::sync::Arc;

pub struct UserRecoveryPasswordDomainService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
{
    recovery_passwd_repo: R,
    security_settings_repo: Arc<S>,
}

impl<R, S> UserRecoveryPasswordDomainService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
{
    pub fn new(recovery_passwd_repo: R, security_settings_repo: Arc<S>) -> Self {
        Self {
            recovery_passwd_repo,
            security_settings_repo,
        }
    }

    pub async fn initiate_password_reset(
        &self,
        request: RecoveryPasswdRequestDTO,
    ) -> Result<RecoveryPasswdResponse, DomainError> {
        let identifier = &request.identifier;
        let user_result = self.identify_user(identifier).await?;
        self.check_account_blocked(&user_result)?;
        self.process_recovery_attempt(user_result, request).await
    }

    pub async fn complete_recovery(
        &self,
        request: UserCompleteRecoveryRequestDTO,
    ) -> Result<UserRecoveryPasswdOutcome, DomainError> {
        UserValidationService::validate_passwd(&request.new_password)?;

        let recovery_request = self
            .recovery_passwd_repo
            .get_recovery_token(&request.token)
            .await?;

        self.check_token_expiry(&recovery_request).await?;

        UserValidationService::validate_blocked_time(
            recovery_request.restore_blocked_until,
            "Recovery account is locked until",
        )?;

        let user_id = UserId::new(&recovery_request.user_id);

        self.validate_ip_ua(&request, &recovery_request, &user_id)
            .await?;

        self.reset_password_and_invalidate_sessions(&request, recovery_request, user_id)
            .await
    }
}

impl<R, S> UserRecoveryPasswordDomainService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
{
    async fn identify_user(&self, identifier: &str) -> Result<UserRecoveryPasswd, DomainError> {
        if EMAIL_REGEX.is_match(identifier) {
            let email = Email::new(identifier);
            UserValidationService::validate_email(&email)?;
            self.recovery_passwd_repo.get_user_by_email(email).await
        } else {
            let username = Username::new(identifier);
            UserValidationService::validate_username(&username)?;
            self.recovery_passwd_repo
                .get_user_by_username(username)
                .await
        }
    }

    fn check_account_blocked(&self, user_result: &UserRecoveryPasswd) -> Result<(), DomainError> {
        if let Some(blocked_until) = user_result.restore_blocked_until {
            let now = Utc::now();
            if now < blocked_until {
                let friendly_date = blocked_until.format("%Y-%m-%d %H:%M UTC").to_string();
                return Err(DomainError::ValidationError(
                    ValidationError::BusinessRuleViolation(format!(
                        "Password restoration is not allowed until the account is unlocked on {}.",
                        friendly_date
                    )),
                ));
            }
        }
        Ok(())
    }

    async fn process_recovery_attempt(
        &self,
        user: UserRecoveryPasswd,
        request: RecoveryPasswdRequestDTO,
    ) -> Result<RecoveryPasswdResponse, DomainError> {
        let duration = Duration::minutes(15);
        let token = SharedDomainService::generate_token(32)?;
        let user_id_dto = UserId::new(&user.user_id);
        let expiry = Utc::now() + duration;
        let token = OtpToken(token);

        self.recovery_passwd_repo
            .prepare_user_restore_passwd(
                user_id_dto,
                expiry,
                token.clone(),
                request.user_agent,
                request.ip_address,
            )
            .await?;

        Ok(RecoveryPasswdResponse {
            email: user.email,
            username: user.username,
            token,
            expiry,
        })
    }

    async fn check_token_expiry(
        &self,
        recovery_request: &UserRecoveryPasswd,
    ) -> Result<(), DomainError> {
        if let Some(expiry) = recovery_request.expiry {
            if expiry < Utc::now() {
                let total_attempt_count = recovery_request.attempt_count + 1;

                let block_duration = if total_attempt_count > 10 {
                    Some(Utc::now() + Duration::hours(1))
                } else if total_attempt_count > 5 {
                    Some(Utc::now() + Duration::minutes(10))
                } else {
                    None
                };

                self.recovery_passwd_repo
                    .update_user_restore_attempts_and_block(
                        &UserId::new(&recovery_request.user_id),
                        total_attempt_count,
                        block_duration,
                    )
                    .await?;

                return Err(DomainError::ValidationError(
                    ValidationError::BusinessRuleViolation(
                        "The recovery token has expired. Please request a new one.".to_string(),
                    ),
                ));
            }
        }
        Ok(())
    }
    async fn validate_ip_ua(
        &self,
        request: &UserCompleteRecoveryRequestDTO,
        recovery_request: &UserRecoveryPasswd,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        if !UserValidationService::validate_ip_ua(
            &request.user_agent,
            &request.ip_address,
            recovery_request.user_agent.as_ref(),
            recovery_request.ip_address.as_ref(),
        ) {
            let total_attempt_count = recovery_request.attempt_count + 1;

            let block_duration = if total_attempt_count > 10 {
                Some(Utc::now() + Duration::hours(1))
            } else if total_attempt_count > 5 {
                Some(Utc::now() + Duration::minutes(10))
            } else {
                None
            };

            self.recovery_passwd_repo
                .update_user_restore_attempts_and_block(
                    &user_id,
                    total_attempt_count,
                    block_duration,
                )
                .await?;

            return Err(DomainError::ValidationError(
                ValidationError::BusinessRuleViolation(
                    "Recovery failed because the IP address or user agent does not match the original request.".to_string(),
                ),
            ));
        }
        Ok(())
    }
    async fn reset_password_and_invalidate_sessions(
        &self,
        request: &UserCompleteRecoveryRequestDTO,
        recovery_request: UserRecoveryPasswd,
        user_id: UserId,
    ) -> Result<UserRecoveryPasswdOutcome, DomainError> {
        let reset_future = self
            .recovery_passwd_repo
            .reset_restore_attempts_and_block(&user_id);

        let pass_hash = UserCredentialService::generate_password_hash(&request.new_password)?;
        let setup_future =
            self.security_settings_repo
                .set_new_password(&user_id, pass_hash, Utc::now());

        let session_invalidation_future = async {
            if recovery_request
                .security_setting
                .close_sessions_on_change_password
            {
                self.security_settings_repo
                    .invalidate_sessions(&user_id)
                    .await
            } else {
                Ok(())
            }
        };

        tokio::try_join!(reset_future, setup_future, session_invalidation_future)?;

        let message = if recovery_request
            .security_setting
            .close_sessions_on_change_password
        {
            "Your password has been successfully reset and all active sessions have been closed for security purposes."
        } else {
            "Your password has been successfully reset.\
         Please remember to manually close any active sessions to ensure your account's security."
        };

        Ok(UserRecoveryPasswdOutcome {
            user_id: recovery_request.user_id,
            email: recovery_request.email,
            message: message.to_string(),
            close_sessions_on_change_password: recovery_request
                .security_setting
                .close_sessions_on_change_password,
        })
    }
}
