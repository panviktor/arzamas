use crate::domain::entities::user::UserRegistration;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreatedUserResponse {
    user_id: String,
    username: String,
    email: String,
    created_at: DateTime<Utc>,
}

impl CreatedUserResponse {
    pub fn new(user_id: &str, username: &str, email: &str, created_at: DateTime<Utc>) -> Self {
        Self {
            user_id: user_id.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            created_at,
        }
    }
}

impl CreatedUserResponse {
    pub fn from(user: UserRegistration) -> Self {
        Self::new(
            &user.user_id,
            &user.username.value(),
            user.email.value(),
            user.created_at,
        )
    }
}
