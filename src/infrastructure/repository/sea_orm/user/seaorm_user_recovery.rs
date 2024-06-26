use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::value_objects::{IPAddress, OtpToken, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_recovery_password::UserRecoveryPasswd;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_recovery_password_repository::UserRecoveryPasswdDomainRepository;
use crate::infrastructure::repository::fetch_model;
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
    async fn get_user_by_email(&self, email: Email) -> Result<UserRecoveryPasswd, DomainError> {
        let user_model = fetch_model::<user::Entity>(
            &self.db,
            user::Column::Email.eq(email.value()),
            "User not found for recovery by email.",
        )
        .await?;

        self.fetch_user_details(user_model).await
    }

    async fn get_user_by_username(
        &self,
        username: Username,
    ) -> Result<UserRecoveryPasswd, DomainError> {
        let user_model = fetch_model::<user::Entity>(
            &self.db,
            user::Column::Username.eq(username.value()),
            "User not found for recovery by username.",
        )
        .await?;
        self.fetch_user_details(user_model).await
    }

    async fn update_user_restore_attempts_and_block(
        &self,
        user: &UserId,
        count: i64,
        block_until: Option<DateTime<Utc>>,
    ) -> Result<(), DomainError> {
        let mut recovery = fetch_model::<user_recovery_password::Entity>(
            &self.db,
            user_recovery_password::Column::UserId.eq(user.user_id.clone()),
            "User not found for updating restore attempts and block.",
        )
        .await?
        .into_active_model();

        recovery.attempt_count = Set(count);
        recovery.restore_blocked_until = Set(block_until.map(|dt| dt.naive_utc()));
        recovery
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn reset_restore_attempts_and_block(&self, user: &UserId) -> Result<(), DomainError> {
        let mut recovery = fetch_model::<user_recovery_password::Entity>(
            &self.db,
            user_recovery_password::Column::UserId.eq(user.user_id.clone()),
            "User not found for recovery.",
        )
        .await?
        .into_active_model();

        recovery.restore_blocked_until = Set(None);
        recovery.attempt_count = Set(0);
        recovery.expiry = Set(None);
        recovery.user_agent = Set(None);
        recovery.ip_address = Set(None);
        recovery.recovery_token = Set(None);

        recovery
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn get_recovery_token(
        &self,
        token: &OtpToken,
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
            let security_setting = fetch_model::<entity::user_security_settings::Entity>(
                &self.db,
                entity::user_security_settings::Column::UserId.eq(user.user_id.clone()),
                "User not found for recovery.",
            )
            .await?
            .into();

            Ok(UserRecoveryPasswd::new(
                recovery.user_id,
                Email::new(&user.email),
                Username::new(&user.username),
                recovery.user_agent.as_deref().map(UserAgent::new),
                recovery.ip_address.as_deref().map(IPAddress::new),
                security_setting,
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
        user: UserId,
        expiry: DateTime<Utc>,
        token: OtpToken,
        user_agent: UserAgent,
        ip_address: IPAddress,
    ) -> Result<(), DomainError> {
        let mut recovery = fetch_model::<user_recovery_password::Entity>(
            &self.db,
            user_recovery_password::Column::UserId.eq(user.user_id.clone()),
            "User not found for preparing restore password.",
        )
        .await?
        .into_active_model();

        recovery.expiry = Set(Some(expiry.naive_utc()));
        recovery.recovery_token = Set(Some(token.into_inner()));
        recovery.user_agent = Set(Some(user_agent.into_inner()));
        recovery.ip_address = Set(Some(ip_address.into_inner()));
        recovery.attempt_count = Set(0);

        recovery
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
        let security_setting = fetch_model::<entity::user_security_settings::Entity>(
            &self.db,
            entity::user_security_settings::Column::UserId.eq(user.user_id.clone()),
            "User security settings not found for recovery.",
        )
        .await?
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
