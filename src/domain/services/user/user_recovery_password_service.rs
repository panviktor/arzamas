use crate::domain::entities::email::EmailMessage;
use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::ports::repositories::user::user_recovery_password_parameters::{
    RecoveryPasswdRequestDTO, RecoveryPasswdResponse, UserCompleteRecoveryRequestDTO,
    UserRecoveryPasswdOutcome,
};
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use crate::domain::services::shared::SharedDomainService;
use crate::domain::services::user::user_validation_service::EMAIL_REGEX;
use crate::domain::services::user::UserValidationService;
use chrono::{Duration, Utc};
use std::sync::Arc;

pub struct UserRecoveryPasswordDomainService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
{
    user_recovery_passwd_repository: R,
    user_security_settings_repository: Arc<S>,
}

impl<R, S> UserRecoveryPasswordDomainService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
{
    pub fn new(
        user_recovery_passwd_repository: R,
        user_security_settings_repository: Arc<S>,
    ) -> Self {
        Self {
            user_recovery_passwd_repository,
            user_security_settings_repository,
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
            .user_recovery_passwd_repository
            .get_recovery_token(request.token)
            .await?;

        UserValidationService::validate_blocked_time(
            recovery_request.restore_blocked_until,
            "Recovery account is locked until",
        )?;

        let user_id = FindUserByIdDTO::new(&recovery_request.user_id);

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

            let block_future = self
                .user_recovery_passwd_repository
                .block_user_restore_until(&user_id, block_duration);

            let attempts_future = self
                .user_recovery_passwd_repository
                .update_user_restore_attempts(&user_id, total_attempt_count);

            tokio::try_join!(block_future, attempts_future)?;

            return Ok(UserRecoveryPasswdOutcome::InvalidToken {
                user_id: recovery_request.user_id,
                email: recovery_request.email,
                message: "Recovery failed because the IP address or user agent does not match the original request.".to_string(),
                email_notifications_enabled: recovery_request
                    .security_setting
                    .email_on_failure_enabled_at,
            });
        }

        // user_security_settings_repository . set new passwd ! (not imp yet)

        todo!()
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
            let email_dto = FindUserByEmailDTO::new(email);
            self.user_recovery_passwd_repository
                .get_user_by_email(email_dto)
                .await
        } else {
            let username = Username::new(identifier);
            UserValidationService::validate_username(&username)?;
            let username_dto = FindUserByUsernameDTO::new(&username);
            self.user_recovery_passwd_repository
                .get_user_by_username(username_dto)
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
        let user_id_dto = FindUserByIdDTO::new(&user.user_id);
        let expiry = Utc::now() + duration;
        let token = EmailToken(token);

        self.user_recovery_passwd_repository
            .prepare_user_restore_passwd(
                user_id_dto,
                expiry,
                token.clone(),
                request.user_agent,
                request.ip_address,
            )
            .await?;

        Ok(RecoveryPasswdResponse {
            user_id: user.user_id.to_string(),
            email: user.email,
            username: user.username,
            token,
            expiry,
        })
    }

    fn is_request_from_trusted_source(
        &self,
        request: &UserCompleteRecoveryRequestDTO,
        user_result: &UserRecoveryPasswd,
    ) -> bool {
        UserValidationService::validate_ip_ua(
            &request.user_agent,
            &request.ip_address,
            user_result.user_agent.as_ref(),
            user_result.ip_address.as_ref(),
        )
    }
}
