use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::{Email, EmailToken};
use crate::domain::ports::repositories::user::user_security_settings_parameters::{
    ActivateEmail2FADTO, ChangeEmailDTO, ChangePasswordDTO, ConfirmEmail2FADTO, ConfirmEmailDTO,
    SecuritySettingsUpdateDTO,
};

/// ChangePasswordRequest
pub struct ChangePasswordRequest {
    pub user_id: String,
    pub current_password: String,
    pub new_password: String,
    pub new_password_confirm: String,
}

impl ChangePasswordRequest {
    pub fn new(
        user_id: String,
        current_password: String,
        new_password: String,
        new_password_confirm: String,
    ) -> Self {
        Self {
            user_id,
            current_password,
            new_password,
            new_password_confirm,
        }
    }
}

impl From<ChangePasswordRequest> for ChangePasswordDTO {
    fn from(request: ChangePasswordRequest) -> Self {
        ChangePasswordDTO {
            user_id: UserId::new(&request.user_id),
            current_password: request.current_password,
            new_password: request.new_password,
        }
    }
}

/// ChangeEmailRequest
pub struct ChangeEmailRequest {
    pub user_id: String,
    pub current_password: String,
    pub new_email: String,
    pub new_email_confirm: String,
}

impl ChangeEmailRequest {
    pub fn new(
        user_id: String,
        current_password: String,
        new_email: String,
        new_email_confirm: String,
    ) -> Self {
        Self {
            user_id,
            current_password,
            new_email,
            new_email_confirm,
        }
    }
}

impl From<ChangeEmailRequest> for ChangeEmailDTO {
    fn from(request: ChangeEmailRequest) -> Self {
        ChangeEmailDTO {
            user_id: UserId::new(&request.user_id),
            current_password: request.current_password,
            new_email: request.new_email,
            new_email_confirm: request.new_email_confirm,
        }
    }
}

/// ConfirmEmailRequest
pub struct ConfirmEmailRequest {
    pub user_id: String,
    pub token: String,
}

impl ConfirmEmailRequest {
    pub fn new(user_id: String, token: String) -> Self {
        Self { user_id, token }
    }
}

impl From<ConfirmEmailRequest> for ConfirmEmailDTO {
    fn from(request: ConfirmEmailRequest) -> Self {
        ConfirmEmailDTO {
            user_id: UserId::new(&request.user_id),
            token: EmailToken::new(&request.token),
        }
    }
}

/// SecuritySettingsUpdateRequest
pub struct SecuritySettingsUpdateRequest {
    pub user_id: String,
    pub email_on_success: Option<bool>,
    pub email_on_failure: Option<bool>,
    pub close_sessions_on_change_password: Option<bool>,
}

impl SecuritySettingsUpdateRequest {
    pub fn new(
        user_id: String,
        email_on_success: Option<bool>,
        email_on_failure: Option<bool>,
        close_sessions_on_change_password: Option<bool>,
    ) -> Self {
        Self {
            user_id,
            email_on_success,
            email_on_failure,
            close_sessions_on_change_password,
        }
    }
}

impl From<SecuritySettingsUpdateRequest> for SecuritySettingsUpdateDTO {
    fn from(request: SecuritySettingsUpdateRequest) -> Self {
        SecuritySettingsUpdateDTO {
            user_id: UserId::new(&request.user_id),
            email_on_success: request.email_on_success,
            email_on_failure: request.email_on_failure,
            close_sessions_on_change_password: request.close_sessions_on_change_password,
        }
    }
}

/// ActivateEmail2FARequest
pub struct ActivateEmail2FARequest {
    pub user_id: String,
    pub email: String,
}

impl ActivateEmail2FARequest {
    pub fn new(user_id: String, email: String) -> Self {
        Self { user_id, email }
    }
}

impl From<ActivateEmail2FARequest> for ActivateEmail2FADTO {
    fn from(request: ActivateEmail2FARequest) -> Self {
        ActivateEmail2FADTO {
            user_id: UserId::new(&request.user_id),
            email: Email::new(&request.email),
        }
    }
}

/// ConfirmEmail2FARequest
pub struct ConfirmEmail2FARequest {
    pub user_id: String,
    pub token: String,
}

impl ConfirmEmail2FARequest {
    pub fn new(user_id: String, token: String) -> Self {
        Self { user_id, token }
    }
}

impl From<ConfirmEmail2FARequest> for ConfirmEmail2FADTO {
    fn from(request: ConfirmEmail2FARequest) -> Self {
        ConfirmEmail2FADTO {
            user_id: UserId::new(&request.user_id),
            email_token: EmailToken::new(&request.token),
        }
    }
}
