/// Represents all possible domain-level errors across the application.
#[derive(Debug)]
pub enum DomainError {
    /// Errors related to persistence operations like CRUD actions.
    PersistenceError(PersistenceError),
    /// Errors related to data validation, including domain-specific rules.
    ValidationError(ValidationError),
    /// Errors resulting from interactions with external services, APIs, etc.
    ExternalServiceError(ExternalServiceError),
    /// Indicates that a requested resource was not found.
    NotFound,
    /// A fallback error for situations not covered by other variants.
    Unknown(String),
}

/// Errors specifically associated with persistence operations (e.g., database actions).
#[derive(Debug)]
pub enum PersistenceError {
    /// Error creating a resource.
    Create(String),
    /// Error retrieving a resource or set of resources.
    Retrieve(String),
    /// Error updating an existing resource.
    Update(String),
    /// Error deleting a resource.
    Delete(String),
    /// A catch-all for persistence errors not explicitly covered above.
    Custom(String),
    /// Error with creating or rollback transaction.
    Transaction(String),
}

/// Errors related to validating data against business rules or constraints.
#[derive(Debug)]
pub enum ValidationError {
    /// Data provided does not meet the necessary criteria.
    InvalidData(String),
    /// A business rule was violated by the provided data or action.
    BusinessRuleViolation(String),
    /// For validation errors that don't fit neatly into the other categories.
    Custom(String),
}

/// Represents errors that occur during interactions with external services.
#[derive(Debug)]
pub enum ExternalServiceError {
    /// An operation timed out.
    Timeout(String),
    /// Connectivity issues were encountered.
    Connectivity(String),
    /// Errors parsing or handling responses from external services.
    ResponseError(String),
    /// For external service errors not covered by the specific cases above.
    Custom(String),
}

use std::fmt;

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::PersistenceError(e) => write!(f, "{}", e),
            DomainError::ValidationError(e) => write!(f, "{}", e),
            DomainError::ExternalServiceError(e) => write!(f, "{}", e),
            DomainError::NotFound => write!(f, "The requested resource was not found"),
            DomainError::Unknown(e) => write!(f, "An unknown error occurred: {}", e),
        }
    }
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistenceError::Create(e) => write!(f, "Error creating resource: {}", e),
            PersistenceError::Retrieve(e) => write!(f, "Error retrieving resource: {}", e),
            PersistenceError::Update(e) => write!(f, "Error updating resource: {}", e),
            PersistenceError::Delete(e) => write!(f, "Error deleting resource: {}", e),
            PersistenceError::Custom(e) => write!(f, "A custom persistence error occurred: {}", e),
            PersistenceError::Transaction(e) => write!(f, "A transaction error occurred: {}", e),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidData(e) => write!(f, "Invalid data provided: {}", e),
            ValidationError::BusinessRuleViolation(e) => {
                write!(f, "Business rule violation: {}", e)
            }
            ValidationError::Custom(e) => write!(f, "A custom validation error occurred: {}", e),
        }
    }
}

impl fmt::Display for ExternalServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExternalServiceError::Timeout(e) => write!(f, "Operation timed out: {}", e),
            ExternalServiceError::Connectivity(e) => {
                write!(f, "Connectivity issues encountered: {}", e)
            }
            ExternalServiceError::ResponseError(e) => {
                write!(f, "Error parsing response from external service: {}", e)
            }
            ExternalServiceError::Custom(e) => {
                write!(f, "A custom external service error occurred: {}", e)
            }
        }
    }
}
