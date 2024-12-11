use serde_derive::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LoginResponse {
    OTPResponse {
        public_token: String,
        message: String,
        needed_types: Vec<AuthType>,
    },
    TokenResponse {
        token: String,
        token_type: String,
    },
    PendingResponse {
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AuthType {
    Email,
    App,
}
