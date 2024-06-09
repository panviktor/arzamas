use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::ports::repositories::user::user_recovery_password_parameters::{
    RecoveryPasswdRequestDTO, RecoveryPasswdResponse,
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
    user_recovery_passwd_repository: Arc<R>,
    user_security_settings_repository: Arc<S>,
}

impl<R, S> UserRecoveryPasswordDomainService<R, S>
where
    R: UserRecoveryPasswdDomainRepository,
    S: UserSecuritySettingsDomainRepository,
{
    pub fn new(
        user_recovery_passwd_repository: Arc<R>,
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
        let duration = Duration::minutes(10);
        let token = SharedDomainService::generate_token(6)?;
        let token_hash = SharedDomainService::hash_token(&token);
        let user_id_dto = FindUserByIdDTO::new(&user.user_id);
        let expiry = Utc::now() + duration;

        self.user_recovery_passwd_repository
            .prepare_user_restore_passwd(
                user_id_dto,
                expiry,
                token_hash,
                request.user_agent,
                request.ip_address,
            )
            .await?;

        Ok(RecoveryPasswdResponse {
            user_id: user.user_id.to_string(),
            email: user.email,
            username: user.username,
            token: EmailToken(token),
            expiry,
        })
    }
}
