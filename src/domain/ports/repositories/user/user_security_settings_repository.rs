use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::todo;

#[async_trait]
pub trait UserSecuritySettingsDomainRepository {
    async fn invalidate_sessions(&self, user: &FindUserByIdDTO) -> Result<(), DomainError>;

    async fn set_new_password(
        &self,
        user: &FindUserByIdDTO,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError>;
    async fn invalidate_session(
        &self,
        user: &FindUserByIdDTO,
        session_id: &str,
    ) -> Result<(), DomainError>;
}

//verify-email
//logout
//logout-all
//current-session
//all-sessions
//change-password
//change-email
//resend-verify-email
//security-settings (get)
//security-settings (post)
//2fa-add-email
//2fa-remove-email
//2fa-add
//2fa-activate
//2fa-reset
//2fa-remove
