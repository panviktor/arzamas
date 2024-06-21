pub struct UserRecoveryRequest {
    pub identifier: String,
    pub user_agent: String,
    pub ip_address: String,
}

impl UserRecoveryRequest {
    pub fn new(identifier: String, user_agent: String, ip_address: String) -> Self {
        Self {
            identifier,
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
        token: String,
        new_password: String,
        password_confirm: String,
        user_agent: String,
        ip_address: String,
    ) -> Self {
        Self {
            token,
            new_password,
            password_confirm,
            user_agent,
            ip_address,
        }
    }
}
