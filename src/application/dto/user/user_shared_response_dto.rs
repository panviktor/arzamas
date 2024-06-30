use crate::domain::entities::user::UserBase;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BaseUserResponse {
    pub user_id: String,
    pub email: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserBase> for BaseUserResponse {
    fn from(user: UserBase) -> Self {
        Self {
            user_id: user.user_id,
            email: user.email.into_inner(),
            username: user.username,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

pub struct UniversalApplicationResponse {
    pub title: String,
    pub subtitle: Option<String>,
}

impl UniversalApplicationResponse {
    pub fn new(title: String, subtitle: Option<String>) -> Self {
        Self { title, subtitle }
    }
}
