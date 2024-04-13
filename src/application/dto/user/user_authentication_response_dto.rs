use serde_derive::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LoginResponse {
    OTPResponse {
        message: String,
        apps_code: bool,
        user_id: String,
    },
    TokenResponse {
        token: String,
        token_type: String,
    },
}
