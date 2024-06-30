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
