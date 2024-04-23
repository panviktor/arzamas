use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::user::user_authentication::UserAuthentication;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::DomainError;
use crate::domain::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

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
    ) -> Result<Vec<UserSession>, DomainError>;

    async fn update_user_login_attempts(
        &self,
        user: FindUserByIdDTO,
        count: i32,
    ) -> Result<(), DomainError>;

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
        user: &FindUserByIdDTO,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError>;

    /// Prepares a user for 2FA by setting up necessary tokens and expiry.
    ///
    /// # Arguments
    /// * `user` - DTO containing the user ID.
    /// * `expiry` - DateTime when the 2FA setup expires.
    /// * `email_token_hash` - Optional hashed token for email-based 2FA.
    /// * `user_agent` - A string representing the user agent of the client initiating the 2FA setup. This can be used for logging purposes or for assessing the security context of the request.
    /// * `ip_address` - The IP address from which the 2FA setup request was made. This can also be used for security logging and might be involved in evaluating the legitimacy of the setup request.
    ///
    /// # Returns
    /// Result indicating success or an error if the setup fails.
    async fn prepare_user_for_2fa(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        email_token_hash: Option<String>,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError>;

    /// Validates if the email-based 2FA setup is still valid.
    ///
    /// # Arguments
    /// * `user` - DTO containing the user ID.
    /// * `expiry` - DateTime to check against the current time.
    /// * `user_agent` - A string representing the user agent of the client initiating the 2FA setup. This can be used for logging purposes or for assessing the security context of the request.
    /// * `ip_address` - The IP address from which the 2FA setup request was made. This can also be used for security logging and might be involved in evaluating the legitimacy of the setup request.
    ///
    /// # Returns
    /// Result indicating if the 2FA email setup is still valid or not.
    async fn validate_2fa_email_with_expiry(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError>;

    /// Validates if the app-based 2FA setup is still valid.
    ///
    /// # Arguments
    /// * `user` - DTO containing the user ID.
    /// * `expiry` - DateTime to check against the current time.
    /// * `user_agent` - A string representing the user agent of the client initiating the 2FA setup. This can be used for logging purposes or for assessing the security context of the request.
    /// * `ip_address` - The IP address from which the 2FA setup request was made. This can also be used for security logging and might be involved in evaluating the legitimacy of the setup request.
    ///
    /// # Returns
    /// Result indicating if the 2FA app setup is still valid or not.
    async fn validate_2f_app_with_expiry(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError>;

    /// Resets the 2FA flow and all login attempts for a user.
    ///
    /// # Arguments
    /// * `user` - DTO containing the user ID.
    ///
    /// # Returns
    /// Result indicating success or an error if the reset fails.
    async fn reset_2fa_flow_and_login_attempts(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<(), DomainError>;
}
