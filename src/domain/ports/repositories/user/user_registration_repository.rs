use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::user_security_settings::UserEmailConfirmation;
use crate::domain::entities::user::UserRegistration;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserRegistrationDomainRepository {
    /// Create the received user entity in the persistence system
    async fn create_user(&self, user: UserRegistration) -> Result<UserRegistration, DomainError>;

    /// Delete the received user entity in the persistence system
    async fn delete_user(&self, user: UserId) -> Result<(), DomainError>;

    async fn store_main_primary_activation_token(
        &self,
        user: UserId,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn get_primary_email_activation(
        &self,
        user_id: &UserId,
    ) -> Result<UserEmailConfirmation, DomainError>;

    async fn complete_primary_email_verification(&self, user: &UserId) -> Result<(), DomainError>;
}
