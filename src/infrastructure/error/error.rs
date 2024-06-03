#[derive(Debug)]
pub enum InfrastructureError {
    /// Errors from database operations
    DatabaseError(String),
    /// Errors from caching mechanisms, e.g., Redis
    CacheError(String),
    /// Errors related to file system operations
    FileSystemError(String),
    /// Errors from external service interactions
    ExternalServiceError(String),
    /// Network-related errors, distinct from business logic or database errors
    NetworkError(String),
    /// Errors in configuration or during the startup phase
    ConfigurationError(String),
    /// General errors that do not fit into the other categories
    Unknown(String),
}
