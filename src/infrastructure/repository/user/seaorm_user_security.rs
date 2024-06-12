use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use entity::{note, user, user_session};
use sea_orm::sea_query::Expr;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, ModelTrait,
    QueryFilter,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmUserSecurityRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserSecurityRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserSecuritySettingsDomainRepository for SeaOrmUserSecurityRepository {
    async fn invalidate_sessions(&self, user: &FindUserByIdDTO) -> Result<(), DomainError> {
        user_session::Entity::update_many()
            .col_expr(user_session::Column::Valid, Expr::value(false))
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .exec(&*self.db)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;
        Ok(())
    }

    async fn set_new_password(
        &self,
        user: &FindUserByIdDTO,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(&user.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found".to_string(),
                ))
            })?;

        let mut active = user_model.into_active_model();
        active.pass_hash = Set(pass_hash);
        active.updated_at = Set(update_time.naive_utc());
        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn invalidate_session(
        &self,
        user: &FindUserByIdDTO,
        session_id: &str,
    ) -> Result<(), DomainError> {
        let session = user_session::Entity::find()
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .filter(user_session::Column::SessionId.eq(session_id))
            .one(&*self.db)
            .await
            .map_err(|_| {
                DomainError::PersistenceError(PersistenceError::Delete(
                    "Database error occurred".to_string(),
                ))
            })?
            .ok_or_else(|| DomainError::NotFound)?;

        let mut active = session.into_active_model();
        active.valid = Set(false);

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }
}
