use crate::domain::entities::shared::Email;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct UserBase {
    pub user_id: String,
    pub email: Email,
    pub username: String,
    pub email_validated: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserBase {
    pub fn new(
        user_id: String,
        email: Email,
        username: String,
        email_validated: bool,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            email,
            username,
            email_validated,
            created_at,
            updated_at,
        }
    }
}
