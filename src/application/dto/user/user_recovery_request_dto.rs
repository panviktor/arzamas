pub struct UserRecoveryRequest {
    pub identifier: String,
    pub user_agent: String,
    pub ip_address: String,
}

impl UserRecoveryRequest {
    pub fn new(identifier: &str, user_agent: String, ip_address: String) -> Self {
        Self {
            identifier: identifier.to_string(),
            user_agent,
            ip_address,
        }
    }
}

pub struct UserCompleteRecoveryRequest {
    pub token: String,
    pub new_password: String,
    pub password_confirm: String,
    pub user_agent: String,
    pub ip_address: String,
}

impl UserCompleteRecoveryRequest {
    pub fn new(
        token: &str,
        new_password: &str,
        password_confirm: &str,
        user_agent: String,
        ip_address: String,
    ) -> Self {
        Self {
            token: token.to_string(),
            new_password: new_password.to_string(),
            password_confirm: password_confirm.to_string(),
            user_agent,
            ip_address,
        }
    }
}
