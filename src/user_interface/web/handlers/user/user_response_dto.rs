use crate::application::dto::user::user_security_response_dto::{
    SecuritySettingsResponse, UserSessionResponse,
};
use crate::application::dto::user::user_shared_response_dto::BaseUserResponse;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};
use utoipa::ToSchema;

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

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SecuritySettingsResponseWeb {
    pub email_on_success: bool,
    pub email_on_failure: bool,
    pub close_sessions_on_change_password: bool,
}

impl From<SecuritySettingsResponse> for SecuritySettingsResponseWeb {
    fn from(response: SecuritySettingsResponse) -> Self {
        SecuritySettingsResponseWeb {
            email_on_success: response.email_on_success,
            email_on_failure: response.email_on_failure,
            close_sessions_on_change_password: response.close_sessions_on_change_password,
        }
    }
}
