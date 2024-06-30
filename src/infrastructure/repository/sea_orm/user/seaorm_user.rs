use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::UserBase;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use crate::infrastructure::repository::fetch_model;
use async_trait::async_trait;
use entity::user;
use sea_orm::ColumnTrait;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmUserSharedRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserSharedRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserSharedDomainRepository for SeaOrmUserSharedRepository {
    async fn exists_with_email(&self, email: &Email) -> Result<bool, DomainError> {
        let user = fetch_model::<user::Entity>(
            &self.db,
            user::Column::Email.eq(email.value()),
            "User not found",
        )
        .await
        .ok();
        Ok(user.is_some())
    }

    async fn exists_with_username(&self, username: &Username) -> Result<bool, DomainError> {
        let user = fetch_model::<user::Entity>(
            &self.db,
            user::Column::Username.eq(username.value()),
            "User not found",
        )
        .await
        .ok();
        Ok(user.is_some())
    }

    async fn get_base_user_by_email(&self, email: Email) -> Result<UserBase, DomainError> {
        let user = fetch_model::<user::Entity>(
            &self.db,
            user::Column::Email.eq(email.value()),
            "Base User not found by email.",
        )
        .await?;
        Ok(user.into())
    }

    async fn get_base_user_by_username(&self, username: Username) -> Result<UserBase, DomainError> {
        let user = fetch_model::<user::Entity>(
            &self.db,
            user::Column::Username.eq(username.value()),
            "Base User not found by username.",
        )
        .await?;
        Ok(user.into())
    }

    async fn get_base_user_by_id(&self, user_id: &UserId) -> Result<UserBase, DomainError> {
        let user = fetch_model::<user::Entity>(
            &self.db,
            user::Column::UserId.eq(&user_id.user_id),
            "Base User not found by user id.",
        )
        .await?;

        Ok(user.into())
    }
}
