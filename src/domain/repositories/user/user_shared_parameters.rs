use crate::domain::entities::shared::{Email, Username};

pub struct FindUserByIdDTO {
    pub user_id: String,
}

impl FindUserByIdDTO {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
        }
    }
}

pub struct FindUserByEmailDTO {
    pub email: Email,
}

pub struct FindUserByUsernameDTO {
    pub username: Username,
}
