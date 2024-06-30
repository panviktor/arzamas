use serde_derive::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Deserialize, IntoParams, Debug)]
pub struct UserByIdRequestWeb {
    pub id: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateUserRequestWeb {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginUserRequestWeb {
    pub identifier: String,
    pub password: String,
    pub persistent: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ContinueLoginRequestWeb {
    pub public_token: String,
    pub code: String,
    pub verification_method: APIVerificationMethodWeb,
}
#[derive(Serialize, Deserialize, ToSchema)]
pub enum APIVerificationMethodWeb {
    EmailOTP,
    AuthenticatorApp,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ValidateEmailRequestWeb {
    pub email: String,
    pub email_token: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserRecoveryRequestWeb {
    pub identifier: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UserCompleteRecoveryRequestWeb {
    pub token: String,
    pub new_password: String,
    pub password_confirm: String,
}
