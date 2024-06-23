pub mod sea_orm;
use crate::domain::error::{DomainError, PersistenceError};
use ::sea_orm::sea_query::SimpleExpr;
use ::sea_orm::{DatabaseConnection, EntityTrait, QueryFilter};
pub async fn fetch_model<M>(
    db: &DatabaseConnection,
    filter: SimpleExpr,
    not_found_error: &str,
) -> Result<M::Model, DomainError>
where
    M: EntityTrait,
{
    M::find()
        .filter(filter)
        .one(db)
        .await
        .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
        .ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(not_found_error.to_string()))
        })
}
