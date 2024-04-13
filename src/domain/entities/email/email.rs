use crate::application::error::error::ApplicationError;
use crate::domain::error::{DomainError, ExternalServiceError};
use chrono::{DateTime, Utc};
use std::fmt;

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub body: String,
}

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

impl EmailMessage {
    pub fn new(to: String, subject: String, body: String) -> Self {
        Self { to, subject, body }
    }
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

impl From<EmailError> for ApplicationError {
    fn from(error: EmailError) -> Self {
        match error {
            EmailError::SendingFailed { message, .. } => {
                ApplicationError::ExternalServiceError(format!("Email Sending Failed: {}", message))
            }
            EmailError::AuthenticationFailed(msg) => ApplicationError::ExternalServiceError(
                format!("Email Authentication Failed: {}", msg),
            ),
            EmailError::RateLimited(next_try) => ApplicationError::ExternalServiceError(format!(
                "Email Rate Limited, retry after: {}",
                next_try
            )),
            EmailError::InvalidRecipient(recipient) => {
                ApplicationError::BadRequest(format!("Invalid Email Recipient: {}", recipient))
            }
            EmailError::Unknown(msg) => {
                ApplicationError::Unknown(format!("Unknown Email Error: {}", msg))
            }
        }
    }
}
