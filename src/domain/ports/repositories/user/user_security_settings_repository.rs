use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::Email;
use crate::domain::entities::user::user_security_settings::{
    DeleteUserConfirmation, User2FAAppConfirmation, User2FAEmailConfirmation,
    UserChangeEmailConfirmation, UserSecuritySettings,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_security_settings_dto::SecuritySettingsUpdateDTO;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserSecuritySettingsDomainRepository {
    async fn invalidate_session(&self, user: &UserId, session_id: &str) -> Result<(), DomainError>;
    async fn invalidate_sessions(&self, user: &UserId) -> Result<(), DomainError>;
    async fn get_user_session(
        &self,
        user: &UserId,
        session_id: &str,
    ) -> Result<UserSession, DomainError>;
    async fn get_user_sessions(&self, user: &UserId) -> Result<Vec<UserSession>, DomainError>;
    async fn get_old_passwd(&self, user: &UserId) -> Result<String, DomainError>;
    async fn set_new_password(
        &self,
        user: &UserId,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn store_change_email_confirmation_token(
        &self,
        user: UserId,
        token: String,
        expiry: DateTime<Utc>,
        new_email: Email,
    ) -> Result<(), DomainError>;
    async fn get_change_email_confirmation(
        &self,
        user: &UserId,
    ) -> Result<UserChangeEmailConfirmation, DomainError>;
    async fn update_main_user_email(
        &self,
        user: &UserId,
        email: Email,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn clear_email_confirmation_token(&self, user: &UserId) -> Result<(), DomainError>;
    async fn get_security_settings(
        &self,
        user: &UserId,
    ) -> Result<UserSecuritySettings, DomainError>;
    async fn update_security_settings(
        &self,
        settings: SecuritySettingsUpdateDTO,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn save_email_2fa_token(
        &self,
        user_id: UserId,
        email_token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn get_email_2fa_token(
        &self,
        user: &UserId,
    ) -> Result<User2FAEmailConfirmation, DomainError>;
    async fn toggle_email_2fa(
        &self,
        user: &UserId,
        enable: bool,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn save_app_2fa_secret(
        &self,
        user_id: UserId,
        secret: String,
        email_token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError>;

    async fn get_app_2fa_token(&self, user: &UserId)
        -> Result<User2FAAppConfirmation, DomainError>;
    async fn toggle_app_2fa(
        &self,
        user: &UserId,
        enable: bool,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;

    async fn store_token_for_remove_user(
        &self,
        user: UserId,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn get_token_for_remove_user(
        &self,
        user: &UserId,
    ) -> Result<DeleteUserConfirmation, DomainError>;
    async fn delete_user(&self, user: UserId) -> Result<(), DomainError>;
}
