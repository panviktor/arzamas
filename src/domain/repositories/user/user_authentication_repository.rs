use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

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

    async fn save_user_session(&self, session: &UserSession) -> Result<(), DomainError>;

    async fn get_user_sessions(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<(Vec<UserSession>), DomainError>;

    async fn update_user_login_attempts(
        &self,
        user: FindUserByIdDTO,
        count: i32,
    ) -> Result<(), DomainError>;

    async fn block_user_until(
        &self,
        user: &FindUserByIdDTO,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError>;

    async fn prepare_user_for_2fa(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        email_token_hash: Option<String>,
    ) -> Result<(), DomainError>;

    async fn update_2fa_session_expiry(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError>;
}
