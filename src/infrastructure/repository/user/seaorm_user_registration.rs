use crate::domain::entities::user::UserRegistration;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::domain::repositories::user::user_shared_parameters::FindUserByIdDTO;
use async_trait::async_trait;
use entity::{
    user, user_confirmation, user_otp_token, user_restore_password, user_security_settings,
};
use sea_orm::ColumnTrait;
use sea_orm::QueryFilter;
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, EntityTrait, Set, TransactionTrait, TryIntoModel,
};
use std::sync::Arc;
#[derive(Clone)]
pub struct SeaOrmUserRegistrationRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserRegistrationRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}
#[async_trait]
impl UserRegistrationDomainRepository for SeaOrmUserRegistrationRepository {
    async fn create_user(&self, user: UserRegistration) -> Result<UserRegistration, DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        let user_email = user.email.clone().into_inner();

        let user_id_clone = user.user_id.clone();
        let user_model = user.into_active_model();

        let user_model = user_model
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_security_settings = user_security_settings::ActiveModel {
            user_id: Set(user_id_clone.clone()),
            ..Default::default()
        };

        user_security_settings
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_confirmation = user_confirmation::ActiveModel {
            user_id: Set(user_id_clone.clone()),
            ..Default::default()
        };

        user_confirmation
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_otp_token = user_otp_token::ActiveModel {
            user_id: Set(user_id_clone.clone()),
            ..Default::default()
        };

        user_otp_token
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_restore_password = user_restore_password::ActiveModel {
            user_id: Set(user_id_clone),
            ..Default::default()
        };

        user_restore_password
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        let domain_user: UserRegistration = user_model.try_into_model()?.into();
        Ok(domain_user)
    }

    async fn delete_user(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        user::Entity::delete_many()
            .filter(user::Column::UserId.eq(user.user_id))
            .exec(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Delete(e.to_string())))?;

        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        Ok(())
    }
}
