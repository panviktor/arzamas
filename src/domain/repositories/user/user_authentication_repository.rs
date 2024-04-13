use crate::domain::entities::user::user_authentication::{EmailToken, UserAuthentication};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;

/// Represents the repository interface for user authentication operations.
/// Provides methods for user lookup, session management, and email verification.
#[async_trait]
pub trait UserAuthenticationDomainRepository {
    async fn get_user_by_email(
        &self,
        query: FindUserByEmailDTO,
    ) -> Result<UserAuthentication, DomainError>;

    async fn get_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserAuthentication, DomainError>;

    async fn save_user_session(&self, session: UserSession) -> Result<(), DomainError>;

    async fn get_user_sessions(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<(Vec<UserSession>), DomainError>;

    async fn save_email_verification_token(
        &self,
        user: FindUserByIdDTO,
        token: EmailToken,
    ) -> Result<(), DomainError>;

    async fn verify_email_auth_token(
        &self,
        user: FindUserByIdDTO,
        token: EmailToken,
    ) -> Result<(), DomainError>;
}
