use crate::application::dto::user::user_authentication_request_dto::APIVerificationMethod;
use crate::domain::repositories::user::user_authentication_parameters::DomainVerificationMethod;
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
    pub password_confirm: String,
    pub persistent: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ContinueLoginRequestWeb {
    pub user_id: String,
    pub verification_method: APIVerificationMethodWeb,
    pub code: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
pub enum APIVerificationMethodWeb {
    EmailOTP,
    AuthenticatorApp,
}

#[derive(Serialize, Deserialize)]
pub struct ValidateEmailRequestWeb {
    pub email: String,
    pub email_token: String,
}
