use std::fmt;

#[derive(Debug, Clone)]
pub enum ApplicationError {
    ValidationError(String),
    NotFound(String),
    BadRequest(String),
    DatabaseError(String),
    InternalServerError(String),
    ExternalServiceError(String),
    Unknown(String),
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplicationError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            ApplicationError::NotFound(msg) => write!(f, "Not found: {}", msg),
            ApplicationError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            ApplicationError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            ApplicationError::InternalServerError(msg) => {
                write!(f, "Internal server error: {}", msg)
            }
            ApplicationError::ExternalServiceError(msg) => {
                write!(f, "External service error: {}", msg)
            }
            ApplicationError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}
