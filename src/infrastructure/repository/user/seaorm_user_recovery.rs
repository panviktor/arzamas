use crate::domain::entities::shared::value_objects::{EmailToken, IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::domain::ports::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::{user, user_recovery_password};
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
};
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
        let recovery = entity::user_recovery_password::Entity::find()
            .filter(user_recovery_password::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found for recovery.".to_string(),
                ))
            })?;
        let mut active = recovery.into_active_model();
        active.attempt_count = Set(count);
        active.restore_blocked_until = Set(block_until.map(|dt| dt.naive_utc()));
        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn reset_restore_attempts_and_block(
        &self,
        user: &FindUserByIdDTO,
    ) -> Result<(), DomainError> {
        let recovery = entity::user_recovery_password::Entity::find()
            .filter(user_recovery_password::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User not found for recovery.".to_string(),
                ))
            })?;
        let mut active = recovery.into_active_model();
        active.restore_blocked_until = Set(None);
        active.attempt_count = Set(0);
        active.expiry = Set(None);
        active.user_agent = Set(None);
        active.ip_address = Set(None);
        active.recovery_token = Set(None);

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn get_recovery_token(
        &self,
        token: &EmailToken,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        let recovery_with_user = entity::user_recovery_password::Entity::find()
            .filter(user_recovery_password::Column::RecoveryToken.eq(token.value()))
            .find_also_related(user::Entity)
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Recovery token not found".to_string(),
                ))
            })?;

        if let (recovery, Some(user)) = recovery_with_user {
            let security_setting = entity::user_security_settings::Entity::find()
                .filter(entity::user_security_settings::Column::UserId.eq(user.user_id.clone()))
                .one(&*self.db)
                .await?
                .ok_or_else(|| {
                    DomainError::PersistenceError(PersistenceError::Retrieve(
                        "User not found for recovery.".to_string(),
                    ))
                })?
                .into();

            Ok(UserRecoveryPasswd::new(
                recovery.user_id,
                Email::new(&user.email),
                Username::new(&user.username),
                recovery.user_agent.as_deref().map(UserAgent::new),
                recovery.ip_address.as_deref().map(IPAddress::new),
                security_setting,
                recovery.recovery_token,
                recovery.expiry.map(|dt| Utc.from_utc_datetime(&dt)),
                recovery.attempt_count,
                recovery
                    .restore_blocked_until
                    .map(|dt| Utc.from_utc_datetime(&dt)),
            ))
        } else {
            Err(DomainError::PersistenceError(PersistenceError::Retrieve(
                "User not found for recovery.".to_string(),
            )))
        }
    }

    async fn prepare_user_restore_passwd(
        &self,
        user: FindUserByIdDTO,
        expiry: DateTime<Utc>,
        token: EmailToken,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError> {
        let recovery_with_user = entity::user_recovery_password::Entity::find()
            .filter(user_recovery_password::Column::UserId.eq(user.user_id.clone()))
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Recovery token not found".to_string(),
                ))
            })?;

        let mut active = recovery_with_user.into_active_model();
        active.expiry = Set(Some(expiry.naive_utc()));
        active.recovery_token = Set(Some(token.into_inner()));
        active.user_agent = Set(Some(user_agent.into_inner()));
        active.ip_address = Set(Some(ip_address.into_inner()));
        active.attempt_count = Set(0);

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
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
                    "User not found for recovery.".to_string(),
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
            None,
            0,
            None,
        ))
    }
}
