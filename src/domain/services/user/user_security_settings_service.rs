use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError, ValidationError};

use crate::domain::error::ValidationError::BusinessRuleViolation;
use crate::domain::ports::repositories::user::user_security_settings_parameters::{
    ActivateEmail2FADTO, ChangeEmailDTO, ChangePasswordDTO, ConfirmEmail2FADTO, ConfirmEmailDTO,
    SecuritySettingsUpdateDTO,
};
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::domain::services::user::UserCredentialService;
use chrono::Utc;
use std::sync::Arc;

pub struct UserSecuritySettingsDomainService<S, U>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
{
    user_security_settings_repository: Arc<S>,
    user_repository: Arc<U>,
}

impl<S, U> UserSecuritySettingsDomainService<S, U>
where
    S: UserSecuritySettingsDomainRepository,
    U: UserSharedDomainRepository,
{
    pub fn new(user_security_settings_repository: Arc<S>, user_repository: Arc<U>) -> Self {
        Self {
            user_security_settings_repository,
            user_repository,
        }
    }

    pub async fn invalidate_sessions(&self, user: UserId) -> Result<(), DomainError> {
        self.user_security_settings_repository
            .invalidate_sessions(&user)
            .await
    }

    pub async fn invalidate_session(
        &self,
        user: UserId,
        session_id: &str,
    ) -> Result<(), DomainError> {
        self.user_security_settings_repository
            .invalidate_session(&user, session_id)
            .await
    }

    pub async fn get_user_session(
        &self,
        user: UserId,
        session_id: &str,
    ) -> Result<UserSession, DomainError> {
        let session = self
            .user_security_settings_repository
            .get_user_session(&user, session_id)
            .await?;
        Ok(session)
    }

    pub async fn get_user_sessions(&self, user: UserId) -> Result<Vec<UserSession>, DomainError> {
        let sessions = self
            .user_security_settings_repository
            .get_user_sessions(&user)
            .await?;
        Ok(sessions)
    }

    pub async fn change_password(&self, request: ChangePasswordDTO) -> Result<(), DomainError> {
        let new_hash = UserCredentialService::generate_password_hash(&request.new_password)
            .map_err(|e| DomainError::Unknown("Password hashing failed".into()))?;

        // Retrieve the old password hash from the database
        let old_db_hash = self
            .user_security_settings_repository
            .get_old_passwd(&request.user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Failed to retrieve old password hash".into(),
                ))
            })?;

        // Validate that the current password matches the stored hash
        match UserCredentialService::credential_validator(&request.current_password, &old_db_hash) {
            Ok(true) => {}
            Ok(false) => {
                return Err(DomainError::ValidationError(ValidationError::InvalidData(
                    "Current password is incorrect".to_string(),
                )));
            }
            Err(e) => {
                return Err(DomainError::Unknown("Credential validation failed".into()));
            }
        }

        // Validate that the new password is different from the old password
        if request.current_password == request.new_password {
            return Err(DomainError::ValidationError(BusinessRuleViolation(
                "New password must be different from the current password".to_string(),
            )));
        }

        //Set the new password in the database
        self.user_security_settings_repository
            .set_new_password(&request.user_id, new_hash, Utc::now())
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Update(
                    "Failed to set new password".into(),
                ))
            })?;
        Ok(())
    }

    pub async fn change_email(&self, request: ChangeEmailDTO) -> Result<EmailToken, DomainError> {
        // let token = SharedDomainService::generate_token(64)?;
        // let confirmation_token = EmailToken::new(&token);
        // let confirmation_token_hash = SharedDomainService::hash_token(&token);
        // let expiry = Utc::now() + Duration::days(1);
        // self.user_repository
        //     .store_email_confirmation_token(request.user_id, confirmation_token_hash, expiry)
        //     .await?;
        //
        // Ok(confirmation_token)

        todo!()
    }

    pub async fn confirm_email(&self, request: ConfirmEmailDTO) -> Result<(), DomainError> {
        todo!()
    }

    pub async fn cancel_email_change(&self, user_id: UserId) -> Result<(), DomainError> {
        self.user_repository
            .clear_email_confirmation_token(user_id)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Update(
                    "Failed to clear email confirmation token".into(),
                ))
            })?;
        Ok(())
    }

    pub async fn get_security_settings(
        &self,
        request: UserId,
    ) -> Result<UserSecuritySettings, DomainError> {
        todo!()
    }

    pub async fn update_security_settings(
        &self,
        request: SecuritySettingsUpdateDTO,
    ) -> Result<(), DomainError> {
        todo!()
    }

    pub async fn enable_email_2fa(
        &self,
        request: ActivateEmail2FADTO,
    ) -> Result<EmailToken, DomainError> {
        todo!()
    }

    pub async fn resend_email_2fa(&self, request: UserId) -> Result<EmailToken, DomainError> {
        todo!()
    }

    pub async fn confirm_email_2fa(&self, request: ConfirmEmail2FADTO) -> Result<(), DomainError> {
        todo!()
    }

    pub async fn disable_email_2fa(&self, request: UserId) -> Result<EmailToken, DomainError> {
        todo!()
    }

    pub async fn confirm_disable_email_2fa(
        &self,
        request: ConfirmEmail2FADTO,
    ) -> Result<(), DomainError> {
        todo!()
    }
}
