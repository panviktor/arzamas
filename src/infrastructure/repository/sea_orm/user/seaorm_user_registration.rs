use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::user_security_settings::UserEmailConfirmation;
use crate::domain::entities::user::UserRegistration;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::infrastructure::repository::fetch_model;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::{
    user, user_authentication, user_confirmation, user_recovery_password, user_security_settings,
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set, TransactionTrait, TryIntoModel};
use sea_orm::{ColumnTrait, IntoActiveModel};
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

        let user_otp_token = user_authentication::ActiveModel {
            user_id: Set(user_id_clone.clone()),
            ..Default::default()
        };

        user_otp_token
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_recovery_password = user_recovery_password::ActiveModel {
            user_id: Set(user_id_clone),
            ..Default::default()
        };

        user_recovery_password
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        let domain_user: UserRegistration = user_model.try_into_model()?.into();
        Ok(domain_user)
    }

    async fn store_main_primary_activation_token(
        &self,
        user: UserId,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let confirmation = self.fetch_user_confirmation(&user.user_id).await?;
        let mut active: user_confirmation::ActiveModel = confirmation.into();
        active.activate_user_token_hash = Set(Some(token));
        active.activate_user_token_expiry = Set(Some(expiry.naive_utc()));
        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }
    async fn get_primary_email_activation(
        &self,
        user_id: &UserId,
    ) -> Result<UserEmailConfirmation, DomainError> {
        let confirmation = self.fetch_user_confirmation(&user_id.user_id).await?;

        let otp_hash = confirmation.activate_user_token_hash.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing OTP hash".to_string(),
            ))
        })?;
        let expiry = confirmation.activate_user_token_expiry.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing expiry date".to_string(),
            ))
        })?;
        let expiry = Utc.from_utc_datetime(&expiry);
        Ok(UserEmailConfirmation { otp_hash, expiry })
    }

    async fn complete_primary_email_verification(&self, user: &UserId) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        // Retrieve the user by user_id within the transaction
        let user = fetch_model::<user::Entity>(
            &self.db,
            user::Column::UserId.eq(&user.user_id),
            "User for email verification not found",
        )
        .await?;

        let mut confirmation = self
            .fetch_user_confirmation(&user.user_id)
            .await?
            .into_active_model();

        // Update the confirmation details to invalidate the OTP and expiry
        confirmation.activate_user_token_hash = Set(None);
        confirmation.activate_user_token_expiry = Set(None);

        // Update the user's email validation status
        let mut active_user: user::ActiveModel = user.into();
        active_user.email_validated = Set(true);

        // Perform the updates within the transaction
        confirmation
            .update(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        active_user
            .update(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        // Commit the transaction
        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        Ok(())
    }
}

impl SeaOrmUserRegistrationRepository {
    async fn fetch_user_confirmation(
        &self,
        user_id: &str,
    ) -> Result<user_confirmation::Model, DomainError> {
        fetch_model::<user_confirmation::Entity>(
            &self.db,
            user_confirmation::Column::UserId.eq(user_id),
            "User confirmation not found",
        )
        .await
    }
}
