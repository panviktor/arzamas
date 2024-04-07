use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LoginUserRequest {
    pub identifier: String,
    pub password: String,
    pub persist: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct OTPCodeRequest {
    pub user_id: String,
    pub email_code: Option<String>,
    pub app_code: Option<String>,
}
