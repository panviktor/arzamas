use crate::domain::entities::shared::{Email, Username};

pub struct CreateUserDTO {
    pub username: Username,
    pub email: Email,
    pub password: String,
}

impl CreateUserDTO {
    pub fn new(username: Username, email: Email, password: String) -> Self {
        Self {
            username,
            email,
            password,
        }
    }
}
