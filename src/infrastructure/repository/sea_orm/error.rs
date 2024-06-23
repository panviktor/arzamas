use crate::domain::error::{DomainError, PersistenceError};

impl From<sea_orm::DbErr> for DomainError {
    fn from(err: sea_orm::DbErr) -> Self {
        DomainError::PersistenceError(PersistenceError::Custom(err.to_string()))
    }
}
