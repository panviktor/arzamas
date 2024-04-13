use crate::application::error::error::ApplicationError;
use crate::domain::error::{DomainError, ExternalServiceError};

#[derive(Debug)]
pub enum CachingError {
    ConnectionFailure(String),
    NotFound(String),
    SerializationError(String),
    DeserializationError(String),
    KeyExpired(String),
    Unknown(String),
}

impl From<CachingError> for DomainError {
    fn from(error: CachingError) -> Self {
        let message = match error {
            CachingError::ConnectionFailure(msg) => format!("Caching Connection Failure: {}", msg),
            CachingError::NotFound(msg) => format!("Cache Not Found: {}", msg),
            CachingError::SerializationError(msg) => {
                format!("Caching Serialization Error: {}", msg)
            }
            CachingError::DeserializationError(msg) => {
                format!("Caching Deserialization Error: {}", msg)
            }
            CachingError::KeyExpired(msg) => format!("Caching Key Expired: {}", msg),
            CachingError::Unknown(msg) => format!("Unknown Caching Error: {}", msg),
        };
        DomainError::ExternalServiceError(ExternalServiceError::Custom(message))
    }
}

impl From<CachingError> for ApplicationError {
    fn from(error: CachingError) -> Self {
        match error {
            CachingError::ConnectionFailure(msg) => ApplicationError::ExternalServiceError(
                format!("Caching Connection Failure: {}", msg),
            ),
            CachingError::NotFound(msg) => {
                ApplicationError::NotFound(format!("Cache Not Found: {}", msg))
            }
            CachingError::SerializationError(msg) => ApplicationError::ExternalServiceError(
                format!("Caching Serialization Error: {}", msg),
            ),
            CachingError::DeserializationError(msg) => ApplicationError::ExternalServiceError(
                format!("Caching Deserialization Error: {}", msg),
            ),
            CachingError::KeyExpired(msg) => {
                ApplicationError::ExternalServiceError(format!("Caching Key Expired: {}", msg))
            }
            CachingError::Unknown(msg) => {
                ApplicationError::Unknown(format!("Unknown Caching Error: {}", msg))
            }
        }
    }
}
