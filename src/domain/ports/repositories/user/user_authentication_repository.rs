use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::value_objects::{OtpCode, UserId};
use crate::domain::entities::shared::{Email, OtpToken, Username};
use crate::domain::entities::user::user_authentication::{
    UserAuthentication, UserAuthenticationData,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Represents the repository interface for user authentication operations.
/// Provides methods for user lookup, session management, and email verification.
#[async_trait]
pub trait UserAuthenticationDomainRepository {
    async fn get_user_by_email(&self, query: Email) -> Result<UserAuthentication, DomainError>;

    async fn get_user_by_username(
        &self,
        username: &Username,
    ) -> Result<UserAuthentication, DomainError>;

    async fn save_user_session(&self, session: &UserSession) -> Result<(), DomainError>;

    async fn update_user_login_attempts(&self, user: UserId, count: i64)
        -> Result<(), DomainError>;

    /// Blocks a user from logging in until a specified time.
    ///
    /// # Arguments
    /// * `user` - DTO containing the user ID.
    /// * `expiry` - Optional DateTime specifying when the block will expire. `None` unblocks the user.
    ///
    /// # Returns
    /// Result indicating success or an error if the operation fails.
    async fn block_user_until(
        &self,
        user: &UserId,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError>;

    async fn prepare_user_for_2fa(
        &self,
        user: UserId,
        otp_public_token: OtpToken,
        email_otp_code_hash: Option<String>,
        code_expiry: DateTime<Utc>,
        user_agent: UserAgent,
        ip_address: IPAddress,
        long_session: bool,
    ) -> Result<(), DomainError>;
    async fn fetch_user_auth_by_token(
        &self,
        otp_public_token: OtpToken,
    ) -> Result<UserAuthenticationData, DomainError>;

    /// Marks the email token as verified for a user.
    ///
    /// # Arguments
    /// * `user` - DTO containing the user ID.
    ///
    /// # Returns
    /// Result indicating success or an error if the verification fails.
    async fn set_email_otp_verified(&self, user: UserId) -> Result<(), DomainError>;

    /// Marks the app OTP token as verified for a user.
    ///
    /// # Arguments
    /// * `user` - DTO containing the user ID.
    ///
    /// # Returns
    /// Result indicating success or an error if the verification fails.
    async fn set_app_otp_verified(&self, user: UserId) -> Result<(), DomainError>;

    /// Resets the OTP validity flags for both email and app-based tokens for a user.
    /// This function is called to ensure that no stale or previously valid tokens
    /// can be used to authenticate, typically after a successful login or when new
    /// tokens are issued.
    async fn reset_otp_validity(&self, user: UserId) -> Result<(), DomainError>;
}
