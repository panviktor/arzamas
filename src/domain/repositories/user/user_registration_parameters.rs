use crate::domain::entities::shared::Email;

pub struct CreateUserDTO {
    pub username: String,
    pub email: Email,
    pub password: String,
}

impl CreateUserDTO {
    pub fn new(username: String, email: Email, password: String) -> Self {
        Self {
            username,
            email,
            password,
        }
    }
}
