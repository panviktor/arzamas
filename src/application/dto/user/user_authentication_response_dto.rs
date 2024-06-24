use serde_derive::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LoginResponse {
    OTPResponse {
        public_token: String,
        message: String,
    },
    TokenResponse {
        token: String,
        token_type: String,
    },
    PendingResponse {
        message: String,
    },
}
