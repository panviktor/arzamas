use crate::application::dto::user::user_authentication_request_dto::APIVerificationMethod;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum LoginResponse {
    OTPResponse {
        public_token: String,
        message: String,
        needed_types: Vec<APIVerificationMethod>,
    },
    TokenResponse {
        token: String,
        token_type: String,
    },
    PendingResponse {
        message: String,
    },
}
