use crate::application::dto::user::user_shared_response_dto::BaseUserResponse;

use crate::application::dto::user::user_security_response_dto::UserSessionResponse;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangePasswordParamsWeb {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

/// Form parameters for changing a user's email.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangeEmailParamsWeb {
    pub current_password: String,
    pub new_email: String,
    pub new_email_confirm: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AboutMeInformationWeb {
    pub name: String,
    pub email: String,
    pub email_validated: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AuthenticationAppInformationWeb {
    pub mnemonic: String,
    pub base32_secret: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct MnemonicConfirmationWeb {
    pub mnemonic: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SecuritySettingsUpdateWeb {
    pub email_on_success_enter: Option<bool>,
    pub email_on_failure_enter: Option<bool>,
    pub close_sessions_on_change_password: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct BaseUserResponseWeb {
    pub user_id: String,
    pub email: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

impl From<BaseUserResponse> for BaseUserResponseWeb {
    fn from(user: BaseUserResponse) -> Self {
        Self {
            user_id: user.user_id,
            email: user.email,
            username: user.username,
            created_at: user.created_at,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct UserSessionResponseWeb {
    pub session_id: String,
    pub session_name: String,
    pub login_timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub expiry: DateTime<Utc>,
    pub valid: bool,
}

impl From<UserSessionResponse> for UserSessionResponseWeb {
    fn from(session: UserSessionResponse) -> Self {
        UserSessionResponseWeb {
            session_id: session.session_id,
            session_name: session.session_name,
            login_timestamp: session.login_timestamp,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            expiry: session.expiry,
            valid: session.valid,
        }
    }
}
