#[derive(Debug, Clone)]
pub struct CreateLoginRequestDTO {
    pub identifier: String,
    pub password: String,
    pub user_agent: String,
    pub ip_address: String,
    pub persistent: bool,
}

impl CreateLoginRequestDTO {
    pub fn new(
        identifier: String,
        password: String,
        user_agent: String,
        ip_address: String,
        persistent: bool,
    ) -> Self {
        Self {
            identifier,
            password,
            user_agent,
            ip_address,
            persistent,
        }
    }
}

#[derive(Debug, Clone)]
pub enum VerificationMethod {
    EmailOTP,
    AuthenticatorApp,
}
#[derive(Debug, Clone)]
pub struct ContinueLoginRequestDTO {
    pub identifier: String,
    pub method: VerificationMethod,
    pub code: String,
    pub user_agent: String,
    pub ip_address: String,
}

impl ContinueLoginRequestDTO {
    pub fn new(
        identifier: String,
        method: VerificationMethod,
        code: String,
        user_agent: String,
        ip_address: String,
    ) -> Self {
        Self {
            identifier,
            method,
            code,
            user_agent,
            ip_address,
        }
    }
}
