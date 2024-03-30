use serde_derive::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
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

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FindUserByIdRequest {
    pub user_id: String,
}
