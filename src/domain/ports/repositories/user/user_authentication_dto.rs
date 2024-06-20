use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};

#[derive(Debug, Clone)]
pub struct CreateLoginRequestDTO {
    pub identifier: String,
    pub password: String,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
    pub persistent: bool,
}

impl CreateLoginRequestDTO {
    pub fn new(
        identifier: String,
        password: String,
        user_agent: UserAgent,
        ip_address: IPAddress,
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
pub enum DomainVerificationMethod {
    EmailOTP,
    AuthenticatorApp,
}
#[derive(Debug, Clone)]
pub struct ContinueLoginRequestDTO {
    pub identifier: String,
    pub verification_method: DomainVerificationMethod,
    pub code: String,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
}

impl ContinueLoginRequestDTO {
    pub fn new(
        identifier: String,
        verification_method: DomainVerificationMethod,
        code: String,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Self {
        Self {
            identifier,
            verification_method,
            code,
            user_agent,
            ip_address,
        }
    }
}
