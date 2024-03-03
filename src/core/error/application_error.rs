use crate::domain::error::DomainError;
use crate::application::error::service_error::ServiceError;
// use crate::core::error::server_error::ServerError;
use crate::infrastructure::repository::error::RepositoryError;

enum ApplicationError {
    DomainError(DomainError),
    RepositoryError(RepositoryError),
    ServiceError(ServiceError),
    // ServerError(ServerError),
}