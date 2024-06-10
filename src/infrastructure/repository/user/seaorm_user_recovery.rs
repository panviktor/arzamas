use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use entity::user;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmUserRecoveryRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserRecoveryRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserRecoveryPasswdDomainRepository for SeaOrmUserRecoveryRepository {
    async fn get_user_by_email(
        &self,
        query: FindUserByEmailDTO,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::Email.eq(query.email.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found for recovery.".to_string(),
                ))
            })?;

        self.fetch_user_details(user_model).await
    }

    async fn get_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        let user_model = entity::user::Entity::find()
            .filter(user::Column::Username.eq(query.username.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found for recovery.".to_string(),
                ))
            })?;
        self.fetch_user_details(user_model).await
    }

    async fn update_user_restore_attempts_and_block(
        &self,
        user: &FindUserByIdDTO,
        count: i64,
        block_until: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError> {
        // let recovery =  entity::user_recovery_password::Entity::find()
        //     .filter(user_recovery_password::)

        todo!()
    }

    async fn get_recovery_token(
        &self,
        token: EmailToken,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        todo!()
    }

    async fn prepare_user_restore_passwd(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        token: EmailToken,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError> {
        todo!()
    }
}

impl SeaOrmUserRecoveryRepository {
    async fn fetch_user_details(
        &self,
        user: user::Model,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        let security_setting = entity::user_security_settings::Entity::find()
            .filter(entity::user_security_settings::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found".to_string(),
                ))
            })?
            .into();

        Ok(UserRecoveryPasswd::new(
            user.user_id,
            Email::new(&user.email),
            Username::new(&user.username),
            None,
            None,
            security_setting,
            None,
            0,
            None,
        ))
    }
}
