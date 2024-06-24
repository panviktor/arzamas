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
