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
