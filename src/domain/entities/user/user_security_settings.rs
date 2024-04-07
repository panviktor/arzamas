pub struct UserSecuritySettings {
    pub user_id: String,
    pub two_factor_email: bool,
    pub two_factor_authenticator_app: bool,
    pub totp_secret: Option<String>,
    pub email_on_success_enabled_at: bool,
    pub email_on_failure_enabled_at: bool,
    pub close_sessions_on_change_password: bool,
}
