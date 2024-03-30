use crate::application::error::error::ApplicationError;
use crate::domain::error::{DomainError, ExternalServiceError, PersistenceError, ValidationError};

pub mod note;
pub mod service_container;
pub mod user;

impl From<DomainError> for ApplicationError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::PersistenceError(pe) => match pe {
                PersistenceError::Create(msg)
                | PersistenceError::Retrieve(msg)
                | PersistenceError::Update(msg)
                | PersistenceError::Delete(msg)
                | PersistenceError::Transaction(msg) => ApplicationError::DatabaseError(msg),
                PersistenceError::Custom(msg) => ApplicationError::DatabaseError(msg),
            },
            DomainError::ValidationError(ve) => match ve {
                ValidationError::InvalidData(msg)
                | ValidationError::BusinessRuleViolation(msg)
                | ValidationError::Custom(msg) => ApplicationError::ValidationError(msg),
            },
            DomainError::ExternalServiceError(ese) => match ese {
                ExternalServiceError::Timeout(msg)
                | ExternalServiceError::Connectivity(msg)
                | ExternalServiceError::ResponseError(msg)
                | ExternalServiceError::Custom(msg) => ApplicationError::InternalServerError(msg),
            },
            DomainError::NotFound => ApplicationError::NotFound("Resource not found.".into()),
            DomainError::Unknown(msg) => ApplicationError::Unknown(msg),
        }
    }
}
