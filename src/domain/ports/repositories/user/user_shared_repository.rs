use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::value_objects::UserEmailConfirmation;
use crate::domain::entities::user::UserBase;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserSharedDomainRepository {
    async fn exists_with_email(&self, email: &Email) -> Result<bool, DomainError>;
    async fn exists_with_username(&self, username: &Username) -> Result<bool, DomainError>;
    async fn get_base_user_by_email(
        &self,
        query: FindUserByEmailDTO,
    ) -> Result<UserBase, DomainError>;

    async fn get_base_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserBase, DomainError>;

    async fn get_base_user_by_id(&self, query: FindUserByIdDTO) -> Result<UserBase, DomainError>;

    async fn store_email_confirmation_token(
        &self,
        user: FindUserByIdDTO,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn retrieve_email_confirmation_token(
        &self,
        user: &FindUserByIdDTO,
    ) -> Result<UserEmailConfirmation, DomainError>;

    async fn complete_email_verification(&self, user: FindUserByIdDTO) -> Result<(), DomainError>;

    async fn invalidate_email_verification(&self, user: FindUserByIdDTO)
        -> Result<(), DomainError>;

    async fn logout_from_sessions(&self, user: FindUserByIdDTO) -> Result<(), DomainError>;
}
