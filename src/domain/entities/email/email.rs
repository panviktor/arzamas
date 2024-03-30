use crate::domain::error::{DomainError, ExternalServiceError};
use std::fmt;

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug)]
pub enum EmailError {
    SendingFailed(String),
}

impl EmailMessage {
    pub fn new(to: String, subject: String, body: String) -> Self {
        Self { to, subject, body }
    }
}

impl From<EmailError> for DomainError {
    fn from(value: EmailError) -> Self {
        match value {
            EmailError::SendingFailed(message) => {
                DomainError::ExternalServiceError(ExternalServiceError::Custom(message))
            }
        }
    }
}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmailError::SendingFailed(message) => write!(f, "Send Error: {}", message),
        }
    }
}
