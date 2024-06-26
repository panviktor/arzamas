use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::Email;
use crate::domain::entities::user::user_security_settings::{
    DeleteUserConfirmation, User2FAAppConfirmation, User2FAEmailConfirmation,
    UserChangeEmailConfirmation, UserSecuritySettings,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError, ValidationError};
use crate::domain::ports::repositories::user::user_security_settings_dto::SecuritySettingsUpdateDTO;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::infrastructure::repository::fetch_model;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::{
    user, user_authentication, user_confirmation, user_recovery_password, user_security_settings,
    user_session,
};
use sea_orm::sea_query::Expr;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
    TransactionTrait,
};
use std::sync::Arc;
use tokio::join;

#[derive(Clone)]
pub struct SeaOrmUserSecurityRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmUserSecurityRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserSecuritySettingsDomainRepository for SeaOrmUserSecurityRepository {
    async fn invalidate_session(&self, user: &UserId, session_id: &str) -> Result<(), DomainError> {
        let session = fetch_model::<user_session::Entity>(
            &self.db,
            user_session::Column::UserId
                .eq(&user.user_id)
                .and(user_session::Column::SessionId.eq(session_id)),
            "Session not found",
        )
        .await?;

        let mut active = session.into_active_model();
        active.valid = Set(false);

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn invalidate_sessions(&self, user: &UserId) -> Result<(), DomainError> {
        user_session::Entity::update_many()
            .col_expr(user_session::Column::Valid, Expr::value(false))
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .exec(&*self.db)
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;
        Ok(())
    }

    async fn get_user_session(
        &self,
        user: &UserId,
        session_id: &str,
    ) -> Result<UserSession, DomainError> {
        let session = fetch_model::<user_session::Entity>(
            &self.db,
            user_session::Column::UserId
                .eq(&user.user_id)
                .and(user_session::Column::SessionId.eq(session_id)),
            "Session not found",
        )
        .await?;

        Ok(session.into())
    }

    async fn get_user_sessions(&self, user: &UserId) -> Result<Vec<UserSession>, DomainError> {
        let sessions: Vec<UserSession> = user_session::Entity::find()
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .all(&*self.db)
            .await
            .map_err(|_| {
                DomainError::PersistenceError(PersistenceError::Delete(
                    "Database error occurred".to_string(),
                ))
            })?
            .into_iter()
            .map(UserSession::from)
            .collect();

        Ok(sessions)
    }

    async fn get_old_passwd(&self, user: &UserId) -> Result<String, DomainError> {
        let user_model = fetch_model::<user::Entity>(
            &self.db,
            user::Column::UserId.eq(&user.user_id),
            "User not found",
        )
        .await?;

        Ok(user_model.pass_hash)
    }

    async fn set_new_password(
        &self,
        user: &UserId,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut user_model = fetch_model::<user::Entity>(
            &self.db,
            user::Column::UserId.eq(&user.user_id),
            "User not found",
        )
        .await?
        .into_active_model();

        user_model.pass_hash = Set(pass_hash);
        user_model.updated_at = Set(update_time.naive_utc());
        user_model
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn store_change_email_confirmation_token(
        &self,
        user: UserId,
        token: String,
        expiry: DateTime<Utc>,
        new_email: Email,
    ) -> Result<(), DomainError> {
        let confirmation = self.get_user_confirmation(&user).await?;

        let mut active: user_confirmation::ActiveModel = confirmation.into();
        active.activate_user_token_hash = Set(Some(token));
        active.activate_user_token_expiry = Set(Some(expiry.naive_utc()));
        active.new_main_email = Set(Some(new_email.into_inner()));

        active
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn get_change_email_confirmation(
        &self,
        user: &UserId,
    ) -> Result<UserChangeEmailConfirmation, DomainError> {
        let confirmation = self.get_user_confirmation(user).await?;

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

    async fn update_main_user_email(
        &self,
        user: &UserId,
        email: Email,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut user = fetch_model::<user::Entity>(
            &self.db,
            user::Column::UserId.eq(&user.user_id),
            "User for update email not found",
        )
        .await?
        .into_active_model();

        user.email = Set(email.into_inner());
        user.update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn clear_email_confirmation_token(&self, user: &UserId) -> Result<(), DomainError> {
        let mut confirmation = self.get_user_confirmation(&user).await?.into_active_model();
        confirmation.activate_user_token_hash = Set(None);
        confirmation.activate_user_token_expiry = Set(None);
        confirmation.new_main_email = Set(None);
        confirmation
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn get_security_settings(
        &self,
        user: &UserId,
    ) -> Result<UserSecuritySettings, DomainError> {
        let security_setting = entity::user_security_settings::Entity::find()
            .filter(entity::user_security_settings::Column::UserId.eq(user.user_id.as_str()))
            .one(&*self.db)
            .await?
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "User security settings not found".to_string(),
                ))
            })?
            .into();
        Ok(security_setting)
    }

    async fn update_security_settings(
        &self,
        settings: SecuritySettingsUpdateDTO,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut ss = fetch_model::<user_security_settings::Entity>(
            &self.db,
            user_security_settings::Column::UserId.eq(settings.user_id.user_id),
            "User security settings not found",
        )
        .await?
        .into_active_model();

        if let Some(email_on_success) = settings.email_on_success {
            ss.email_on_success_enabled_at = Set(email_on_success);
        }
        if let Some(email_on_failure) = settings.email_on_failure {
            ss.email_on_failure_enabled_at = Set(email_on_failure);
        }
        if let Some(close_sessions_on_change_password) = settings.close_sessions_on_change_password
        {
            ss.close_sessions_on_change_password = Set(close_sessions_on_change_password);
        }

        ss.update(&*self.db).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to update user security settings: {}",
                e
            )))
        })?;

        Ok(())
    }

    async fn save_email_2fa_token(
        &self,
        user_id: UserId,
        email_token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut uc = fetch_model::<user_confirmation::Entity>(
            &self.db,
            user_confirmation::Column::UserId.eq(user_id.user_id),
            "User confirmation not found",
        )
        .await?
        .into_active_model();

        uc.activate_email2_fa_token = Set(Some(email_token_hash));
        uc.activate_email2_fa_token_expiry = Set(Some(expiry.naive_utc()));

        uc.update(&*self.db).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to save email 2fa activating token: {}",
                e
            )))
        })?;

        Ok(())
    }

    async fn get_email_2fa_token(
        &self,
        user: &UserId,
    ) -> Result<User2FAEmailConfirmation, DomainError> {
        let uc_future = entity::user_confirmation::Entity::find()
            .filter(user_confirmation::Column::UserId.eq(&user.user_id))
            .one(&*self.db);

        let bu_future = entity::user::Entity::find()
            .filter(user::Column::UserId.eq(&user.user_id))
            .one(&*self.db);

        let (uc, bu) = tokio::try_join!(uc_future, bu_future)?;

        let user_confirmation = uc.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "User security settings not found".to_string(),
            ))
        })?;

        let base_security = bu.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Base user settings not found".to_string(),
            ))
        })?;

        if let Some(token) = user_confirmation.activate_email2_fa_token {
            if let Some(expiry) = user_confirmation.activate_email2_fa_token_expiry {
                let expiry_utc: DateTime<Utc> = Utc.from_utc_datetime(&expiry);
                return Ok(User2FAEmailConfirmation::new(
                    token,
                    expiry_utc,
                    Email::new(&base_security.email),
                ));
            }
        }

        Err(DomainError::ValidationError(ValidationError::InvalidData(
            "2FA token or its expiry date not found.".to_string(),
        )))
    }

    async fn toggle_email_2fa(
        &self,
        user: &UserId,
        enable: bool,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut ss = fetch_model::<user_security_settings::Entity>(
            &self.db,
            user_security_settings::Column::UserId.eq(&user.user_id),
            "User security settings not found",
        )
        .await?
        .into_active_model();

        ss.two_factor_email = Set(enable);
        ss.update(&*self.db).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to update email 2FA settings: {}",
                e
            )))
        })?;

        Ok(())
    }

    async fn save_app_2fa_secret(
        &self,
        user_id: UserId,
        secret: String,
        email_token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(format!(
                "Failed to begin transaction: {}",
                e
            )))
        })?;

        let (uc_result, ss_result) = join!(
            fetch_model::<user_confirmation::Entity>(
                &self.db,
                user_confirmation::Column::UserId.eq(&user_id.user_id),
                "User confirmation not found"
            ),
            fetch_model::<user_security_settings::Entity>(
                &self.db,
                user_security_settings::Column::UserId.eq(user_id.user_id),
                "User security settings not found"
            )
        );

        let mut uc = uc_result?.into_active_model();
        let mut ss = ss_result?.into_active_model();

        uc.activate_app2_fa_token = Set(Some(email_token_hash));
        uc.activate_app2_fa_token_expiry = Set(Some(expiry.naive_utc()));
        ss.totp_secret = Set(Some(secret));

        ss.update(&txn).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to save TOTP secret: {}",
                e
            )))
        })?;

        uc.update(&txn).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to save email 2fa activating token: {}",
                e
            )))
        })?;

        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(format!(
                "Failed to commit transaction: {}",
                e
            )))
        })?;

        Ok(())
    }

    async fn get_app_2fa_token(
        &self,
        user: &UserId,
    ) -> Result<User2FAAppConfirmation, DomainError> {
        let uc_future = entity::user_confirmation::Entity::find()
            .filter(user_confirmation::Column::UserId.eq(&user.user_id))
            .one(&*self.db);

        let ss_future = entity::user_security_settings::Entity::find()
            .filter(user_security_settings::Column::UserId.eq(&user.user_id))
            .one(&*self.db);

        let (confirmation, security) = tokio::try_join!(uc_future, ss_future)?;

        let confirmation = confirmation.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Model user confirmation not found".to_string(),
            ))
        })?;

        let security = security.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Base user settings not found".to_string(),
            ))
        })?;

        let otp_hash = confirmation.activate_app2_fa_token.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "OTP hash not found".to_string(),
            ))
        })?;

        let expiry = confirmation.activate_app2_fa_token_expiry.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Token expiry not found".to_string(),
            ))
        })?;

        let expiry_utc = Utc.from_utc_datetime(&expiry);

        let secret = security.totp_secret.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "TOTP secret not found".to_string(),
            ))
        })?;

        Ok(User2FAAppConfirmation::new(otp_hash, expiry_utc, secret))
    }

    async fn toggle_app_2fa(
        &self,
        user: &UserId,
        enable: bool,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(format!(
                "Failed to begin transaction: {}",
                e
            )))
        })?;

        let (uc_result, ss_result, bs_result) = join!(
            fetch_model::<user_confirmation::Entity>(
                &self.db,
                user_confirmation::Column::UserId.eq(&user.user_id),
                "User confirmation not found"
            ),
            fetch_model::<user_security_settings::Entity>(
                &self.db,
                user_security_settings::Column::UserId.eq(&user.user_id),
                "User security settings not found"
            ),
            fetch_model::<user::Entity>(
                &self.db,
                user::Column::UserId.eq(&user.user_id),
                "User not found",
            )
        );

        let mut confirmation = uc_result?.into_active_model();
        let mut security = ss_result?.into_active_model();
        let mut base_user = bs_result?.into_active_model();

        security.two_factor_authenticator_app = Set(enable);
        confirmation.activate_app2_fa_token = Set(None);
        confirmation.activate_app2_fa_token_expiry = Set(None);
        base_user.updated_at = Set(update_time.naive_utc());

        security.update(&txn).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to save TOTP secret: {}",
                e
            )))
        })?;

        confirmation.update(&txn).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to save email 2fa activating token: {}",
                e
            )))
        })?;

        base_user.update(&txn).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to save email 2fa activating token: {}",
                e
            )))
        })?;

        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(format!(
                "Failed to commit transaction: {}",
                e
            )))
        })?;

        Ok(())
    }

    async fn store_token_for_remove_user(
        &self,
        user: UserId,
        token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut confirmation = self.get_user_confirmation(&user).await?.into_active_model();
        confirmation.remove_user_token_hash = Set(Some(token_hash));
        confirmation.activate_user_token_expiry = Set(Some(expiry.naive_utc()));
        confirmation
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn get_token_for_remove_user(
        &self,
        user: &UserId,
    ) -> Result<DeleteUserConfirmation, DomainError> {
        let confirmation = self.get_user_confirmation(&user).await?;

        let token_hash = confirmation.remove_user_token_hash.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing remove user token hash".to_string(),
            ))
        })?;
        let expiry = confirmation.activate_user_token_expiry.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing token expiry date".to_string(),
            ))
        })?;
        let expiry_utc = Utc.from_utc_datetime(&expiry);

        Ok(DeleteUserConfirmation {
            otp_hash: token_hash,
            expiry: expiry_utc,
        })
    }

    async fn delete_user(&self, user: UserId) -> Result<(), DomainError> {
        let txn = self.db.begin().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        user_session::Entity::delete_many()
            .filter(user_session::Column::UserId.eq(&user.user_id))
            .exec(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Delete(e.to_string())))?;

        user_authentication::Entity::delete_many()
            .filter(user_authentication::Column::UserId.eq(&user.user_id))
            .exec(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Delete(e.to_string())))?;

        user_confirmation::Entity::delete_many()
            .filter(user_confirmation::Column::UserId.eq(&user.user_id))
            .exec(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Delete(e.to_string())))?;

        user_recovery_password::Entity::delete_many()
            .filter(user_recovery_password::Column::UserId.eq(&user.user_id))
            .exec(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Delete(e.to_string())))?;

        user_security_settings::Entity::delete_many()
            .filter(user_security_settings::Column::UserId.eq(&user.user_id))
            .exec(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Delete(e.to_string())))?;

        user::Entity::delete_many()
            .filter(user::Column::UserId.eq(&user.user_id))
            .exec(&txn)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Delete(e.to_string())))?;

        txn.commit().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Transaction(e.to_string()))
        })?;

        Ok(())
    }
}

impl SeaOrmUserSecurityRepository {
    async fn get_user_confirmation(
        &self,
        user_id: &UserId,
    ) -> Result<user_confirmation::Model, DomainError> {
        fetch_model::<user_confirmation::Entity>(
            &self.db,
            user_confirmation::Column::UserId.eq(&user_id.user_id),
            "User confirmation not found",
        )
        .await
    }
}
