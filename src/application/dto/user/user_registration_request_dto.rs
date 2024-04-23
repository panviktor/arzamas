use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}
impl CreateUserRequest {
    pub fn new(username: &str, email: &str, password: &str, password_confirm: &str) -> Self {
        Self {
            username: username.to_string(),
            email: email.to_string(),
            password: password.to_string(),
            password_confirm: password_confirm.to_string(),
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
    pub fn new(email: &str, email_token: &str) -> Self {
        Self {
            email: email.to_string(),
            email_token: email_token.to_string(),
        }
    }
}
