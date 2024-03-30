use crate::domain::entities::shared::Email;
use crate::domain::error::{DomainError, ValidationError};
use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
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
}

impl ValidationServiceError {
    fn to_string(&self) -> String {
        match self {
            ValidationServiceError::TooShort(msg) => msg.clone(),
            ValidationServiceError::TooLong(msg) => msg.clone(),
            ValidationServiceError::Mismatch(msg) => msg.clone(),
            ValidationServiceError::InvalidFormat(msg) => msg.clone(),
        }
    }
}

impl UserValidationService {
    pub fn validate_password(password: &str) -> Result<(), ValidationServiceError> {
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

    pub fn validate_username(username: &str) -> Result<(), ValidationServiceError> {
        if username.is_empty() {
            Err(ValidationServiceError::TooShort(
                "Username cannot be empty.".to_string(),
            ))
        } else if username.len() < 3 {
            Err(ValidationServiceError::TooShort(
                "Username must be at least 3 characters.".to_string(),
            ))
        } else if username.bytes().len() > 8192 {
            Err(ValidationServiceError::TooLong(
                "Username too long. Maximum allowed is 8192 bytes.".to_string(),
            ))
        } else if EMAIL_REGEX.is_match(username) {
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
}

impl From<ValidationServiceError> for DomainError {
    fn from(error: ValidationServiceError) -> Self {
        match error {
            ValidationServiceError::TooShort(msg)
            | ValidationServiceError::TooLong(msg)
            | ValidationServiceError::Mismatch(msg)
            | ValidationServiceError::InvalidFormat(msg) => {
                DomainError::ValidationError(ValidationError::InvalidData(msg))
            }
        }
    }
}

impl fmt::Display for ValidationServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationServiceError::TooShort(msg)
            | ValidationServiceError::TooLong(msg)
            | ValidationServiceError::Mismatch(msg)
            | ValidationServiceError::InvalidFormat(msg) => write!(f, "{}", msg),
        }
    }
}
