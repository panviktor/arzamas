use serde_derive::{Deserialize, Serialize};

/// Struct for holding the form parameters with the new user form
#[derive(Serialize, Deserialize)]
pub struct ChangePasswordParams {
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

/// Form parameters for changing a user's email.
#[derive(Serialize, Deserialize)]
pub struct ChangeEmailParams {
    pub current_password: String,
    pub new_email: String,
    pub new_email_confirm: String,
}

#[derive(Serialize, Deserialize)]
pub struct AboutMeInformation {
    pub name: String,
    pub email: String,
    pub email_validated: bool,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticationAppInformation {
    pub mnemonic: String,
    pub base32_secret: String,
}
