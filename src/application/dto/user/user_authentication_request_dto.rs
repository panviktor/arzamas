use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::ports::repositories::user::user_authentication_parameters::{
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
        identifier: &str,
        password: &str,
        user_agent: &str,
        ip_address: &str,
        persistent: bool,
    ) -> Self {
        Self {
            identifier: identifier.to_string(),
            password: password.to_string(),
            user_agent: user_agent.to_string(),
            ip_address: ip_address.to_string(),
            persistent,
        }
    }
}

pub enum APIVerificationMethod {
    EmailOTP,
    AuthenticatorApp,
}

pub struct OTPVerificationRequest {
    pub user_id: String,
    pub verification_method: APIVerificationMethod,
    pub code: String,
    pub user_agent: String,
    pub ip_address: String,
}

impl OTPVerificationRequest {
    pub fn new(
        user_id: String,
        verification_method: APIVerificationMethod,
        code: String,
        user_agent: String,
        ip_address: String,
    ) -> Self {
        Self {
            user_id,
            verification_method,
            code,
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
            identifier: request.user_id,
            verification_method: request.verification_method.into(),
            code: request.code,
            user_agent: UserAgent::new(&request.user_agent),
            ip_address: IPAddress::new(&request.ip_address),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct UserToken {
    pub user_id: String,
    pub session_id: String,
    pub session_name: String,
    pub login_timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub expiry: DateTime<Utc>,
}

impl From<UserSession> for UserToken {
    fn from(session: UserSession) -> Self {
        UserToken {
            user_id: session.user_id,
            session_id: session.session_id,
            session_name: session.session_name,
            login_timestamp: session.login_timestamp,
            user_agent: session.user_agent.into_inner(),
            ip_address: session.ip_address.into_inner(),
            expiry: session.expiry,
        }
    }
}
