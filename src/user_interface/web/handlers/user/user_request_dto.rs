use serde_derive::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangePasswordRequestWeb {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangeEmailRequestWeb {
    pub new_email: String,
    pub new_email_confirm: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ConfirmEmailRequestWeb {
    pub email_token: String,
}
#[derive(Serialize, Deserialize, ToSchema)]
pub struct SecuritySettingsUpdateRequestWeb {
    pub email_on_success: Option<bool>,
    pub email_on_failure: Option<bool>,
    pub close_sessions_on_change_password: Option<bool>,
}
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ActivateEmail2FARequestWeb {
    pub email: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangeApp2FAStateRequestWeb {
    pub email_code: String,
    pub code: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ConfirmEmail2FARequestWeb {
    pub token: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ConfirmDeleteUserWeb {
    pub token: String,
}
