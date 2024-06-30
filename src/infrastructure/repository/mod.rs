pub mod sea_orm;
use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::error::{DomainError, PersistenceError};
use ::sea_orm::sea_query::SimpleExpr;
use ::sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction,
    EntityTrait, IntoActiveModel, QueryFilter, TransactionTrait,
};
use entity::{user, user_confirmation, user_credentials, user_security_settings};

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

async fn update_model<M>(
    txn: &DatabaseTransaction,
    model: M,
    error_message: &str,
) -> Result<(), DomainError>
where
    M: ActiveModelTrait + Send + Sync + ActiveModelBehavior,
    <<M as ActiveModelTrait>::Entity as EntityTrait>::Model: IntoActiveModel<M>,
{
    model.update(txn).await.map(|_| ()).map_err(|e| {
        DomainError::PersistenceError(PersistenceError::Update(format!(
            "{}: {}",
            error_message, e
        )))
    })
}

pub async fn begin_transaction(
    db: &DatabaseConnection,
) -> Result<DatabaseTransaction, DomainError> {
    db.begin().await.map_err(|e| {
        DomainError::PersistenceError(PersistenceError::Transaction(format!(
            "Failed to begin transaction: {}",
            e
        )))
    })
}

async fn commit_transaction(txn: DatabaseTransaction) -> Result<(), DomainError> {
    txn.commit().await.map_err(|e| {
        DomainError::PersistenceError(PersistenceError::Transaction(format!(
            "Failed to commit transaction: {}",
            e
        )))
    })
}

async fn fetch_user(db: &DatabaseConnection, user_id: &UserId) -> Result<user::Model, DomainError> {
    fetch_model::<user::Entity>(
        db,
        user::Column::UserId.eq(&user_id.user_id),
        "User not found",
    )
    .await
}

async fn fetch_user_confirmation(
    db: &DatabaseConnection,
    user_id: &UserId,
) -> Result<user_confirmation::Model, DomainError> {
    fetch_model::<user_confirmation::Entity>(
        db,
        user_confirmation::Column::UserId.eq(&user_id.user_id),
        "User confirmation not found",
    )
    .await
}

async fn fetch_user_security_settings(
    db: &DatabaseConnection,
    user_id: &UserId,
) -> Result<user_security_settings::Model, DomainError> {
    fetch_model::<user_security_settings::Entity>(
        db,
        user_security_settings::Column::UserId.eq(&user_id.user_id),
        "User security settings not found",
    )
    .await
}

async fn fetch_user_credentials(
    db: &DatabaseConnection,
    user_id: &UserId,
) -> Result<user_credentials::Model, DomainError> {
    fetch_model::<user_credentials::Entity>(
        db,
        user_credentials::Column::UserId.eq(&user_id.user_id),
        "User credentials not found",
    )
    .await
}
