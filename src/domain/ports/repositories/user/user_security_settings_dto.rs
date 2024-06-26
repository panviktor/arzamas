use crate::domain::entities::shared::value_objects::{OtpCode, UserId};
use crate::domain::entities::shared::{Email, OtpToken};

#[derive(Debug)]
pub struct ChangePasswordDTO {
    pub user_id: UserId,
    pub current_password: String,
    pub new_password: String,
}

pub struct ChangeEmailDTO {
    pub user_id: UserId,
    pub new_email: Email,
}

pub struct ConfirmEmailDTO {
    pub user_id: UserId,
    pub token: OtpToken,
}

pub struct SecuritySettingsUpdateDTO {
    pub user_id: UserId,
    pub email_on_success: Option<bool>,
    pub email_on_failure: Option<bool>,
    pub close_sessions_on_change_password: Option<bool>,
}

pub struct ActivateEmail2FADTO {
    pub user_id: UserId,
    pub email: Email,
}

pub struct ConfirmEmail2FADTO {
    pub user_id: UserId,
    pub token: OtpToken,
}

pub struct ConfirmDeleteUserDTO {
    pub user_id: UserId,
    pub token: OtpToken,
}

pub struct ConfirmEnableApp2FADTO {
    pub user_id: UserId,
    pub email_code: OtpCode,
    pub app_code: OtpCode,
}
