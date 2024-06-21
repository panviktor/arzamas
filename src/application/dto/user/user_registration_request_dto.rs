use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}

impl CreateUserRequest {
    pub fn new(
        username: String,
        email: String,
        password: String,
        password_confirm: String,
    ) -> Self {
        Self {
            username,
            email,
            password,
            password_confirm,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FindUserByIdRequest {
    pub user_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct ValidateEmailRequest {
    pub email: String,
    pub email_token: String,
}

impl ValidateEmailRequest {
    pub fn new(email: String, email_token: String) -> Self {
        Self { email, email_token }
    }
}
