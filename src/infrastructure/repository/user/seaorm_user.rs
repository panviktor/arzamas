use crate::domain::entities::shared::value_objects::EmailToken;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::value_objects::UserEmailConfirmation;
use crate::domain::error::DomainError;
use crate::domain::error::PersistenceError;
use crate::domain::repositories::user::user_shared_parameters::FindUserByIdDTO;
use crate::domain::repositories::user::user_shared_repository::UserDomainRepository;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use entity::user;
use sea_orm::ColumnTrait;
use sea_orm::QueryFilter;
use sea_orm::{DatabaseConnection, EntityTrait};
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmUserRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserDomainRepository for SeaOrmUserRepository {
    async fn exists_with_email(&self, email: &Email) -> Result<bool, DomainError> {
        let email_str = email.value();
        let user = entity::prelude::User::find()
            .filter(user::Column::Email.eq(email_str))
            .one(&*self.db)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;

        Ok(user.is_some())
    }

    async fn exists_with_username(&self, username: &Username) -> Result<bool, DomainError> {
        let user_str = username.value();
        let user = entity::prelude::User::find()
            .filter(user::Column::Username.eq(user_str))
            .one(&*self.db)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;

        Ok(user.is_some())
    }

    async fn store_email_confirmation_token(
        &self,
        user: FindUserByIdDTO,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        todo!()
    }

    async fn retrieve_email_confirmation_token(
        &self,
        user: &FindUserByIdDTO,
    ) -> Result<UserEmailConfirmation, DomainError> {
        todo!()
    }

    async fn complete_email_verification(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        todo!()
    }

    async fn invalidate_email_verification(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<(), DomainError> {
        todo!()
    }
}
