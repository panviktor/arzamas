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
