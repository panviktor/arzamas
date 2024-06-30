use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::user::user_security_settings::UserEmailConfirmation;
use crate::domain::entities::user::UserRegistration;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::user::user_registration_repository::UserRegistrationDomainRepository;
use crate::infrastructure::repository::{
    fetch_model, fetch_user_confirmation, fetch_user_credentials,
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::{
    user, user_authentication, user_confirmation, user_credentials, user_recovery_password,
    user_security_settings,
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set, TransactionTrait};
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
    async fn create_user(&self, user: &UserRegistration) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        let user_name_str = user.username.value().to_string();

        let base_user = user::ActiveModel {
            user_id: Set(user.user_id.clone()),
            email: Set(user.email.to_string()),
            username: Set(user_name_str),
            created_at: Set(user.created_at.naive_utc()),
            updated_at: Set(user.created_at.naive_utc()),
            ..Default::default()
        };

        base_user
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_credentials = user_credentials::ActiveModel {
            user_id: Set(user.user_id.clone()),
            pass_hash: Set(user.pass_hash.to_string()),
            updated_at: Set(user.created_at.naive_utc()),
            ..Default::default()
        };

        user_credentials
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_security_settings = user_security_settings::ActiveModel {
            user_id: Set(user.user_id.clone()),
            updated_at: Set(user.created_at.naive_utc()),
            ..Default::default()
        };

        user_security_settings
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_confirmation = user_confirmation::ActiveModel {
            user_id: Set(user.user_id.clone()),
            ..Default::default()
        };

        user_confirmation
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_otp_token = user_authentication::ActiveModel {
            user_id: Set(user.user_id.clone()),
            ..Default::default()
        };

        user_otp_token
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        let user_recovery_password = user_recovery_password::ActiveModel {
            user_id: Set(user.user_id.clone()),
            ..Default::default()
        };

        user_recovery_password
            .save(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        Ok(())
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

    async fn get_user_email_validation_state(&self, user_id: &UserId) -> Result<bool, DomainError> {
        let credentials = fetch_user_credentials(&self.db, &user_id).await?;
        Ok(credentials.email_validated)
    }

    async fn complete_primary_email_verification(
        &self,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        let mut credentials = fetch_user_credentials(&self.db, &user_id)
            .await?
            .into_active_model();

        // Update the user's email validation status
        credentials.email_validated = Set(true);

        let mut confirmation = fetch_user_confirmation(&self.db, &user_id)
            .await?
            .into_active_model();
        credentials
            .update(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        // Update the confirmation details to invalidate the OTP and expiry
        confirmation.activate_user_token_hash = Set(None);
        confirmation.activate_user_token_expiry = Set(None);
        confirmation
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
