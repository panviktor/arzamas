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

impl FindUserByEmailDTO {
    pub fn new(email: Email) -> Self {
        Self { email }
    }
}

pub struct FindUserByUsernameDTO {
    pub username: Username,
}

impl FindUserByUsernameDTO {
    pub fn new(username: &Username) -> Self {
        Self {
            username: username.clone(),
        }
    }
}
