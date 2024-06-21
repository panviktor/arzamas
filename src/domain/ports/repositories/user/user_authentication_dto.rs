use crate::domain::entities::shared::value_objects::{IPAddress, OtpCode, UserAgent};
use crate::domain::entities::shared::OtpToken;

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
    pub public_token: OtpToken,
    pub otp_code: OtpCode,
    pub verification_method: DomainVerificationMethod,
    pub user_agent: UserAgent,
    pub ip_address: IPAddress,
}

impl ContinueLoginRequestDTO {
    pub fn new(
        otp_token: OtpToken,
        otp_code: OtpCode,
        verification_method: DomainVerificationMethod,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Self {
        Self {
            public_token: otp_token,
            otp_code,
            verification_method,
            user_agent,
            ip_address,
        }
    }
}
