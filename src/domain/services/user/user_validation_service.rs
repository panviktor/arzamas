use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::error::{DomainError, ValidationError};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;

lazy_static! {
    pub static ref EMAIL_REGEX: Regex = Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.-]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap();
}

pub struct UserValidationService;

#[derive(Debug, Clone)]
pub enum ValidationServiceError {
    TooShort(String),
    TooLong(String),
    Mismatch(String),
    InvalidFormat(String),
    BusinessRuleViolation(String),
}

impl UserValidationService {
    pub fn validate_passwd(password: &str) -> Result<(), ValidationServiceError> {
        if password.len() < 10 {
            Err(ValidationServiceError::TooShort(
                "Password must be at least 10 characters.".to_string(),
            ))
        } else if password.bytes().len() > 8192 {
            Err(ValidationServiceError::TooLong(
                "Password too long. Maximum allowed is 8192 bytes.".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn validate_username(username: &Username) -> Result<(), ValidationServiceError> {
        if username.value().is_empty() {
            Err(ValidationServiceError::TooShort(
                "Username cannot be empty.".to_string(),
            ))
        } else if username.value().len() < 3 {
            Err(ValidationServiceError::TooShort(
                "Username must be at least 3 characters.".to_string(),
            ))
        } else if username.value().bytes().len() > 8192 {
            Err(ValidationServiceError::TooLong(
                "Username too long. Maximum allowed is 8192 bytes.".to_string(),
            ))
        } else if EMAIL_REGEX.is_match(username.value()) {
            Err(ValidationServiceError::InvalidFormat(
                "Username may not be an email.".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn validate_email(email: &Email) -> Result<(), ValidationServiceError> {
        if !EMAIL_REGEX.is_match(email.value()) {
            Err(ValidationServiceError::InvalidFormat(
                "Invalid email format.".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn validate_blocked_time(
        time: Option<DateTime<Utc>>,
        msg: &str,
    ) -> Result<(), ValidationServiceError> {
        if let Some(blocked_until) = time {
            let now = Utc::now();
            if now < blocked_until {
                let friendly_date = blocked_until.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                return Err(ValidationServiceError::BusinessRuleViolation(format!(
                    "{}: {}",
                    msg, friendly_date
                )));
            }
        }
        Ok(())
    }

    pub fn validate_ip_ua(
        request_user_agent: &UserAgent,
        request_ip_address: &IPAddress,
        stored_user_agent: Option<&UserAgent>,
        stored_ip_address: Option<&IPAddress>,
    ) -> bool {
        match (stored_user_agent, stored_ip_address) {
            (Some(ua), Some(ip)) => request_user_agent == ua && request_ip_address == ip,
            _ => false,
        }
    }
}

impl From<ValidationServiceError> for DomainError {
    fn from(error: ValidationServiceError) -> Self {
        let msg = match error {
            ValidationServiceError::TooShort(msg)
            | ValidationServiceError::TooLong(msg)
            | ValidationServiceError::Mismatch(msg)
            | ValidationServiceError::BusinessRuleViolation(msg)
            | ValidationServiceError::InvalidFormat(msg) => msg,
        };
        DomainError::ValidationError(ValidationError::InvalidData(msg))
    }
}

impl fmt::Display for ValidationServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationServiceError::TooShort(msg)
            | ValidationServiceError::TooLong(msg)
            | ValidationServiceError::Mismatch(msg)
            | ValidationServiceError::InvalidFormat(msg) => write!(f, "{}", msg),
            ValidationServiceError::BusinessRuleViolation(msg) => write!(f, "{}", msg),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip_ua_both_match() {
        let request_user_agent = UserAgent::new("Mozilla/5.0");
        let request_ip_address = IPAddress::new("192.168.1.1");

        let stored_user_agent = UserAgent::new("Mozilla/5.0");
        let stored_ip_address = IPAddress::new("192.168.1.1");

        assert!(UserValidationService::validate_ip_ua(
            &request_user_agent,
            &request_ip_address,
            Some(&stored_user_agent),
            Some(&stored_ip_address)
        ));
    }

    #[test]
    fn test_validate_ip_ua_user_agent_does_not_match() {
        let request_user_agent = UserAgent::new("Mozilla/5.0");
        let request_ip_address = IPAddress::new("192.168.1.1");

        let stored_user_agent = UserAgent::new("DifferentUserAgent");
        let stored_ip_address = IPAddress::new("192.168.1.1");

        assert!(!UserValidationService::validate_ip_ua(
            &request_user_agent,
            &request_ip_address,
            Some(&stored_user_agent),
            Some(&stored_ip_address)
        ));
    }

    #[test]
    fn test_validate_ip_ua_ip_address_does_not_match() {
        let request_user_agent = UserAgent::new("Mozilla/5.0");
        let request_ip_address = IPAddress::new("192.168.1.1");

        let stored_user_agent = UserAgent::new("Mozilla/5.0");
        let stored_ip_address = IPAddress::new("10.0.0.1");

        assert!(!UserValidationService::validate_ip_ua(
            &request_user_agent,
            &request_ip_address,
            Some(&stored_user_agent),
            Some(&stored_ip_address)
        ));
    }
}
