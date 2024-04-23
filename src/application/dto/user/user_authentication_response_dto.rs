use serde_derive::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LoginResponse {
    OTPResponse { user_id: String, message: String },
    TokenResponse { token: String, token_type: String },
}
