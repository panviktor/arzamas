use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;

#[async_trait]
pub trait UserSecuritySettingsDomainRepository {
    async fn logout_all_sessions(&self, user: FindUserByIdDTO) -> Result<(), DomainError>;
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
