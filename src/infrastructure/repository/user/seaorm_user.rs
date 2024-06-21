use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_security_settings::{
    UserChangeEmailConfirmation, UserEmailConfirmation,
};
use crate::domain::entities::user::UserBase;
use crate::domain::error::DomainError;
use crate::domain::error::PersistenceError;
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::{user, user_confirmation};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, TransactionTrait};
use sea_orm::{DatabaseConnection, EntityTrait};
use sea_orm::{IntoActiveModel, QueryFilter};
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

    async fn get_base_user_by_email(&self, email: Email) -> Result<UserBase, DomainError> {
        let user = entity::prelude::User::find()
            .filter(user::Column::Email.eq(email.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Base User not found by email.".to_string(),
                ))
            })?;

        Ok(user.into())
    }

    async fn get_base_user_by_username(&self, username: Username) -> Result<UserBase, DomainError> {
        let user = entity::prelude::User::find()
            .filter(user::Column::Username.eq(username.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Base User not found by username.".to_string(),
                ))
            })?;

        Ok(user.into())
    }

    async fn get_base_user_by_id(&self, user_id: &UserId) -> Result<UserBase, DomainError> {
        let user = entity::prelude::User::find()
            .filter(user::Column::UserId.eq(&user_id.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Base User not found by user id.".to_string(),
                ))
            })?;

        Ok(user.into())
    }

    async fn store_email_confirmation_token(
        &self,
        user: UserId,
        token: String,
        expiry: DateTime<Utc>,
        new_email: Option<Email>,
    ) -> Result<(), DomainError> {
        let confirmation = self.get_user_confirmation(&user).await?;

        let mut active: user_confirmation::ActiveModel = confirmation.into();
        active.activate_user_token_hash = Set(Some(token));
        active.activate_user_token_expiry = Set(Some(expiry.naive_utc()));

        if let Some(email) = new_email {
            active.new_main_email = Set(Some(email.into_inner()));
        }

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn retrieve_email_activation(
        &self,
        user_id: &UserId,
    ) -> Result<UserEmailConfirmation, DomainError> {
        let confirmation = self.get_user_confirmation(user_id).await?;

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

    async fn retrieve_change_email_confirmation(
        &self,
        user_id: &UserId,
    ) -> Result<UserChangeEmailConfirmation, DomainError> {
        let confirmation = self.get_user_confirmation(user_id).await?;

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
        if let Some(new_email) = confirmation.new_main_email {
            let expiry = Utc.from_utc_datetime(&expiry);
            return Ok(UserChangeEmailConfirmation {
                otp_hash,
                expiry,
                new_email: Email::new(&new_email),
            });
        }
        Err(DomainError::PersistenceError(PersistenceError::Retrieve(
            "Missing new email".to_string(),
        )))
    }

    async fn complete_email_verification(&self, user: &UserId) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        // Retrieve the user by user_id within the transaction
        let user = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(&user.user_id))
            .one(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User for email verification not found.".to_string(),
                ))
            })?;

        // Retrieve the user's confirmation details within the transaction
        let confirmation = entity::prelude::UserConfirmation::find()
            .filter(user_confirmation::Column::UserId.eq(&user.user_id))
            .one(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| DomainError::NotFound)?;

        // Update the confirmation details to invalidate the OTP and expiry
        let mut active_confirmation = confirmation.into_active_model();
        active_confirmation.activate_user_token_hash = Set(None);
        active_confirmation.activate_user_token_expiry = Set(None);

        // Update the user's email validation status
        let mut active_user: user::ActiveModel = user.into();
        active_user.email_validated = Set(true);

        // Perform the updates within the transaction
        active_confirmation
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

    async fn update_user_main_email(&self, user: &UserId, email: Email) -> Result<(), DomainError> {
        let user = entity::prelude::User::find()
            .filter(user::Column::UserId.eq(&user.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User for update email not found".to_string(),
                ))
            })?;

        let mut active = user.into_active_model();
        active.email = Set(email.into_inner());
        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn invalidate_email_verification(&self, user: UserId) -> Result<(), DomainError> {
        let user = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(&user.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User for invalidate email verification not found.".to_string(),
                ))
            })?;

        let mut active: user::ActiveModel = user.into();
        active.email_validated = Set(false);

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn clear_email_confirmation_token(&self, user: UserId) -> Result<(), DomainError> {
        let confirmation = self.get_user_confirmation(&user).await?;
        let mut active: user_confirmation::ActiveModel = confirmation.into();
        active.activate_user_token_hash = Set(None);
        active.activate_user_token_expiry = Set(None);
        active.new_main_email = Set(None);
        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }
}

impl SeaOrmUserSharedRepository {
    async fn get_user_confirmation(
        &self,
        user_id: &UserId,
    ) -> Result<user_confirmation::Model, DomainError> {
        entity::prelude::UserConfirmation::find()
            .filter(user_confirmation::Column::UserId.eq(&user_id.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| DomainError::NotFound)
    }
}
