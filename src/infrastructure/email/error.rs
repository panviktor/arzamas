use crate::domain::error::{DomainError, ExternalServiceError, ValidationError};
use chrono::{DateTime, Utc};
use std::fmt;

#[derive(Debug)]
pub enum EmailError {
    SendingFailed {
        message: String,
        recipient: String,
        error_code: Option<i32>,
    },
    AuthenticationFailed(String),
    RateLimited(DateTime<Utc>),
    InvalidRecipient(String),
    Unknown(String),
}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmailError::SendingFailed {
                message,
                recipient,
                error_code,
            } => {
                write!(
                    f,
                    "Failed to send email to {}: {} (Error Code: {:?})",
                    recipient, message, error_code
                )
            }
            EmailError::AuthenticationFailed(msg) => write!(f, "Authentication Error: {}", msg),
            EmailError::RateLimited(next_try) => {
                write!(f, "Rate Limited. Try again after: {}", next_try)
            }
            EmailError::InvalidRecipient(recipient) => {
                write!(f, "Invalid recipient: {}", recipient)
            }
            EmailError::Unknown(msg) => write!(f, "Unknown email error: {}", msg),
        }
    }
}

impl From<EmailError> for DomainError {
    fn from(error: EmailError) -> Self {
        match error {
            EmailError::SendingFailed { message, .. } => DomainError::ExternalServiceError(
                ExternalServiceError::Custom(format!("Failed to send email: {}", message)),
            ),
            EmailError::AuthenticationFailed(msg) => DomainError::ExternalServiceError(
                ExternalServiceError::Custom(format!("Email authentication failed: {}", msg)),
            ),
            EmailError::RateLimited(next_try) => {
                DomainError::ExternalServiceError(ExternalServiceError::Custom(format!(
                    "Email rate limited, retry after: {}",
                    next_try
                )))
            }
            EmailError::InvalidRecipient(recipient) => DomainError::ValidationError(
                ValidationError::InvalidData(format!("Invalid email recipient: {}", recipient)),
            ),
            EmailError::Unknown(msg) => DomainError::ExternalServiceError(
                ExternalServiceError::Custom(format!("Unknown email error: {}", msg)),
            ),
        }
    }
}
