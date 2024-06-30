use crate::domain::entities::shared::value_objects::{IPAddress, OtpCode, UserAgent};
use crate::domain::entities::shared::OtpToken;
use crate::domain::ports::repositories::user::user_authentication_dto::{
    ContinueLoginRequestDTO, DomainVerificationMethod,
};
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

pub struct LoginUserRequest {
    pub identifier: String,
    pub password: String,
    pub user_agent: String,
    pub ip_address: String,
    pub persistent: bool,
}

impl LoginUserRequest {
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

pub enum APIVerificationMethod {
    EmailOTP,
    AuthenticatorApp,
}

pub struct OTPVerificationRequest {
    pub public_token: String,
    pub otp_code: String,
    pub verification_method: APIVerificationMethod,
    pub user_agent: String,
    pub ip_address: String,
}

impl OTPVerificationRequest {
    pub fn new(
        public_token: String,
        otp_code: String,
        verification_method: APIVerificationMethod,
        user_agent: String,
        ip_address: String,
    ) -> Self {
        Self {
            public_token,
            otp_code,
            verification_method,
            user_agent,
            ip_address,
        }
    }
}

impl From<APIVerificationMethod> for DomainVerificationMethod {
    fn from(method: APIVerificationMethod) -> Self {
        match method {
            APIVerificationMethod::EmailOTP => DomainVerificationMethod::EmailOTP,
            APIVerificationMethod::AuthenticatorApp => DomainVerificationMethod::AuthenticatorApp,
        }
    }
}

impl From<OTPVerificationRequest> for ContinueLoginRequestDTO {
    fn from(request: OTPVerificationRequest) -> Self {
        ContinueLoginRequestDTO {
            public_token: OtpToken::new(&request.public_token),
            otp_code: OtpCode::new(&request.otp_code),
            verification_method: DomainVerificationMethod::from(request.verification_method),
            user_agent: UserAgent::new(&request.user_agent),
            ip_address: IPAddress::new(&request.ip_address),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserToken {
    pub user_id: String,
    pub session_id: String,
    pub session_name: String,
    pub login_timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub exp: u64,
}
