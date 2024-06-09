use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;
use entity::user_session;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
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
    async fn invalidate_sessions(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        user_session::Entity::update_many()
            .col_expr(user_session::Column::Valid, Expr::value(false))
            .filter(user_session::Column::UserId.eq(user.user_id.to_string()))
            .exec(&*self.db)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;
        Ok(())
    }
}
