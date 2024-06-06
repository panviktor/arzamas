use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::value_objects::UserEmailConfirmation;
use crate::domain::entities::user::UserBase;
use crate::domain::error::DomainError;
use crate::domain::error::PersistenceError;
use crate::domain::ports::repositories::user::user_shared_parameters::{
    FindUserByEmailDTO, FindUserByIdDTO, FindUserByUsernameDTO,
};
use crate::domain::ports::repositories::user::user_shared_repository::UserSharedDomainRepository;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::{user, user_confirmation};
use sea_orm::ActiveValue::Set;
use sea_orm::QueryFilter;
use sea_orm::{ActiveModelTrait, ColumnTrait};
use sea_orm::{DatabaseConnection, EntityTrait};
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

    async fn get_base_user_by_email(
        &self,
        query: FindUserByEmailDTO,
    ) -> Result<UserBase, DomainError> {
        let user = entity::prelude::User::find()
            .filter(user::Column::Email.eq(query.email.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Base User not found by email.".to_string(),
                ))
            })?;

        let user = UserBase {
            user_id: user.user_id,
            email: Email::new(&user.email),
            username: user.username,
            email_validated: user.email_validated,
            created_at: Utc.from_utc_datetime(&user.created_at),
            updated_at: Utc.from_utc_datetime(&user.updated_at),
        };
        Ok(user)
    }

    async fn get_base_user_by_username(
        &self,
        query: FindUserByUsernameDTO,
    ) -> Result<UserBase, DomainError> {
        let user = entity::prelude::User::find()
            .filter(user::Column::Username.eq(query.username.value()))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Base User not found by username.".to_string(),
                ))
            })?;

        let user = UserBase {
            user_id: user.user_id,
            email: Email::new(&user.email),
            username: user.username,
            email_validated: user.email_validated,
            created_at: Utc.from_utc_datetime(&user.created_at),
            updated_at: Utc.from_utc_datetime(&user.updated_at),
        };
        Ok(user)
    }

    async fn store_email_confirmation_token(
        &self,
        user: FindUserByIdDTO,
        token: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let user_id = user.user_id;
        let confirmation = entity::prelude::UserConfirmation::find()
            .filter(user_confirmation::Column::UserId.eq(user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| DomainError::NotFound)?;

        let mut active: user_confirmation::ActiveModel = confirmation.into();
        active.otp_hash = Set(Some(token));
        active.expiry = Set(Some(expiry.naive_utc()));

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn retrieve_email_confirmation_token(
        &self,
        user_id: &FindUserByIdDTO,
    ) -> Result<UserEmailConfirmation, DomainError> {
        let confirmation = entity::prelude::UserConfirmation::find()
            .filter(user_confirmation::Column::UserId.eq(&user_id.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| DomainError::NotFound)?;

        let otp_hash = confirmation.otp_hash.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing OTP hash".to_string(),
            ))
        })?;
        let expiry = confirmation.expiry.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing expiry date".to_string(),
            ))
        })?;

        let expiry = Utc.from_utc_datetime(&expiry);

        Ok(UserEmailConfirmation { otp_hash, expiry })
    }

    async fn complete_email_verification(&self, user: FindUserByIdDTO) -> Result<(), DomainError> {
        let user = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(user.user_id))
            .one(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User for email verification not found.".to_string(),
                ))
            })?;

        let mut active: user::ActiveModel = user.into();
        active.email_validated = Set(true);

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn invalidate_email_verification(
        &self,
        user: FindUserByIdDTO,
    ) -> Result<(), DomainError> {
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
}
