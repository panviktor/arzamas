use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::value_objects::UserEmailConfirmation;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserDomainRepository {
    async fn exists_with_email(&self, email: &Email) -> Result<bool, DomainError>;
    async fn exists_with_username(&self, username: &Username) -> Result<bool, DomainError>;
    async fn store_email_confirmation_token(
        &self,
        user: FindUserByIdDTO,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn retrieve_email_confirmation_token(
        &self,
        user: &FindUserByEmailDTO,
    ) -> Result<UserEmailConfirmation, DomainError>;

    async fn complete_email_verification(
        &self,
        user: FindUserByEmailDTO,
    ) -> Result<(), DomainError>;

    async fn invalidate_email_verification(&self, user: FindUserByIdDTO)
        -> Result<(), DomainError>;
}
