use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_security_settings::UserChangeEmailConfirmation;
use crate::domain::entities::user::UserBase;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::todo;

#[async_trait]
pub trait UserSharedDomainRepository {
    async fn exists_with_email(&self, email: &Email) -> Result<bool, DomainError>;
    async fn exists_with_username(&self, username: &Username) -> Result<bool, DomainError>;
    async fn get_base_user_by_email(&self, email: Email) -> Result<UserBase, DomainError>;

    async fn get_base_user_by_username(&self, username: Username) -> Result<UserBase, DomainError>;

    async fn get_base_user_by_id(&self, query: &UserId) -> Result<UserBase, DomainError>;

    async fn store_email_confirmation_token(
        &self,
        user: UserId,
        token: String,
        expiry: DateTime<Utc>,
        new_email: Option<Email>,
    ) -> Result<(), DomainError>;
    async fn retrieve_email_confirmation_token(
        &self,
        user: &UserId,
    ) -> Result<UserChangeEmailConfirmation, DomainError>;

    async fn complete_email_verification(&self, user: &UserId) -> Result<(), DomainError>;
    async fn update_user_main_email(&self, user: &UserId, email: Email) -> Result<(), DomainError>;

    async fn invalidate_email_verification(&self, user: UserId) -> Result<(), DomainError>;
    async fn clear_email_confirmation_token(&self, user: UserId) -> Result<(), DomainError>;
}
