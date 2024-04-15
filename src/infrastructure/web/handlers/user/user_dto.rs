use serde_derive::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangePasswordParamsWeb {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

/// Form parameters for changing a user's email.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangeEmailParamsWeb {
    pub current_password: String,
    pub new_email: String,
    pub new_email_confirm: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AboutMeInformationWeb {
    pub name: String,
    pub email: String,
    pub email_validated: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AuthenticationAppInformationWeb {
    pub mnemonic: String,
    pub base32_secret: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct MnemonicConfirmationWeb {
    pub mnemonic: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SecuritySettingsUpdateWeb {
    pub email_on_success_enter: Option<bool>,
    pub email_on_failure_enter: Option<bool>,
    pub close_sessions_on_change_password: Option<bool>,
}