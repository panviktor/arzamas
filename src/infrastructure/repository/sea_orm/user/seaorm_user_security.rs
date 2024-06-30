use crate::domain::entities::shared::value_objects::UserId;
use crate::domain::entities::shared::Email;
use crate::domain::entities::user::user_security_settings::{
    ConfirmDisableApp2FA, DeleteUserConfirmation, User2FAAppConfirmation, User2FAEmailConfirmation,
    UserChangeEmailConfirmation, UserSecuritySettings,
};
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::error::{DomainError, PersistenceError, ValidationError};
use crate::domain::ports::repositories::user::user_security_settings_dto::SecuritySettingsUpdateDTO;
use crate::domain::ports::repositories::user::user_security_settings_repository::UserSecuritySettingsDomainRepository;
use crate::infrastructure::repository::{
    begin_transaction, commit_transaction, fetch_model, fetch_user, fetch_user_confirmation,
    fetch_user_credentials, fetch_user_security_settings, update_model,
};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use entity::{
    user, user_authentication, user_confirmation, user_credentials, user_recovery_password,
    user_security_settings, user_session,
};
use sea_orm::sea_query::Expr;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, QueryFilter,
};
use std::sync::Arc;

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

    async fn get_old_passwd(&self, user_id: &UserId) -> Result<String, DomainError> {
        let user_credentials = fetch_user_credentials(&self.db, &user_id).await?;
        Ok(user_credentials.pass_hash)
    }

    async fn set_new_password(
        &self,
        user_id: &UserId,
        pass_hash: String,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut user_credentials = fetch_user_credentials(&self.db, &user_id)
            .await?
            .into_active_model();

        user_credentials.pass_hash = Set(pass_hash);
        user_credentials.updated_at = Set(update_time.naive_utc());
        user_credentials
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;
        Ok(())
    }

    async fn store_change_email_confirmation_token(
        &self,
        user_id: UserId,
        token: String,
        expiry: DateTime<Utc>,
        new_email: Email,
    ) -> Result<(), DomainError> {
        let mut confirmation = fetch_user_confirmation(&*self.db, &user_id)
            .await?
            .into_active_model();

        confirmation.activate_user_token_hash = Set(Some(token));
        confirmation.activate_user_token_expiry = Set(Some(expiry.naive_utc()));
        confirmation.new_main_email = Set(Some(new_email.into_inner()));

        confirmation
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;
        Ok(())
    }

    async fn get_change_email_confirmation(
        &self,
        user_id: &UserId,
    ) -> Result<UserChangeEmailConfirmation, DomainError> {
        let confirmation = fetch_user_confirmation(&self.db, user_id).await?;

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
        user_id: &UserId,
        email: Email,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut user = fetch_user(&self.db, &user_id).await?.into_active_model();

        user.email = Set(email.into_inner());
        user.updated_at = Set(update_time.naive_utc());
        user.update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn clear_email_confirmation_token(&self, user_id: &UserId) -> Result<(), DomainError> {
        let mut confirmation = fetch_user_confirmation(&self.db, &user_id)
            .await?
            .into_active_model();

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
        user_id: &UserId,
    ) -> Result<UserSecuritySettings, DomainError> {
        let user_security_settings = fetch_user_security_settings(&self.db, &user_id)
            .await?
            .into();
        Ok(user_security_settings)
    }

    async fn update_security_settings(
        &self,
        settings: SecuritySettingsUpdateDTO,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut user_security_settings = fetch_user_security_settings(&self.db, &settings.user_id)
            .await?
            .into_active_model();

        if let Some(email_on_success) = settings.email_on_success {
            user_security_settings.email_on_success_enabled_at = Set(email_on_success);
        }
        if let Some(email_on_failure) = settings.email_on_failure {
            user_security_settings.email_on_failure_enabled_at = Set(email_on_failure);
        }
        if let Some(close_sessions_on_change_password) = settings.close_sessions_on_change_password
        {
            user_security_settings.close_sessions_on_change_password =
                Set(close_sessions_on_change_password);
        }

        user_security_settings.updated_at = Set(update_time.naive_utc());

        user_security_settings
            .update(&*self.db)
            .await
            .map_err(|e| {
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
        let mut confirmation = fetch_user_confirmation(&self.db, &user_id)
            .await?
            .into_active_model();

        confirmation.activate_email2_fa_token = Set(Some(email_token_hash));
        confirmation.activate_email2_fa_token_expiry = Set(Some(expiry.naive_utc()));

        confirmation.update(&*self.db).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to save email 2fa activating token: {}",
                e
            )))
        })?;

        Ok(())
    }

    async fn get_email_2fa_token(
        &self,
        user_id: &UserId,
    ) -> Result<User2FAEmailConfirmation, DomainError> {
        let user_confirmation = fetch_user_confirmation(&self.db, &user_id).await?;

        if let Some(token) = user_confirmation.activate_email2_fa_token {
            if let Some(expiry) = user_confirmation.activate_email2_fa_token_expiry {
                let expiry_utc: DateTime<Utc> = Utc.from_utc_datetime(&expiry);
                return Ok(User2FAEmailConfirmation::new(token, expiry_utc));
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
        let txn = begin_transaction(&self.db).await?;
        let (confirmation, security) = self.fetch_user_confirmation_and_security(user).await?;

        let mut confirmation = confirmation.into_active_model();
        confirmation.activate_email2_fa_token_expiry = Set(None);
        confirmation.activate_email2_fa_token = Set(None);

        let mut security = security.into_active_model();
        security.two_factor_email = Set(enable);
        security.updated_at = Set(update_time.naive_utc());

        update_model(
            &txn,
            confirmation,
            "Failed to update email 2FA activation token",
        )
        .await?;

        update_model(&txn, security, "Failed to update email 2FA setting").await?;
        commit_transaction(txn).await?;
        Ok(())
    }

    async fn save_app_2fa_secret(
        &self,
        user_id: UserId,
        secret: String,
        email_token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let txn = begin_transaction(&self.db).await?;

        let (user_confirmation, user_credentials) = self
            .fetch_user_confirmation_and_credentials(&user_id)
            .await?;

        let mut user_confirmation = user_confirmation.into_active_model();
        let mut user_credentials = user_credentials.into_active_model();

        user_confirmation.activate_app2_fa_token = Set(Some(email_token_hash));
        user_confirmation.activate_app2_fa_token_expiry = Set(Some(expiry.naive_utc()));
        user_credentials.totp_secret = Set(Some(secret));

        update_model(
            &txn,
            user_confirmation,
            "Failed to save email 2FA activating token",
        )
        .await?;

        update_model(&txn, user_credentials, "Failed to save TOTP secret").await?;
        commit_transaction(txn).await?;

        Ok(())
    }

    async fn get_app_2fa_token(
        &self,
        user_id: &UserId,
    ) -> Result<User2FAAppConfirmation, DomainError> {
        let (user_confirmation, user_credentials) = self
            .fetch_user_confirmation_and_credentials(&user_id)
            .await?;

        let otp_hash = user_confirmation.activate_app2_fa_token.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "OTP hash not found".to_string(),
            ))
        })?;

        let expiry = user_confirmation
            .activate_app2_fa_token_expiry
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Token expiry not found".to_string(),
                ))
            })?;

        let expiry_utc = Utc.from_utc_datetime(&expiry);

        let secret = user_credentials.totp_secret.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "TOTP secret not found".to_string(),
            ))
        })?;

        Ok(User2FAAppConfirmation::new(otp_hash, expiry_utc, secret))
    }

    async fn toggle_app_2fa(
        &self,
        user_id: &UserId,
        enable: bool,
        update_time: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let txn = begin_transaction(&self.db).await?;

        let (user_confirmation, user_security_settings) =
            self.fetch_user_confirmation_and_security(user_id).await?;

        let mut user_confirmation = user_confirmation.into_active_model();
        user_confirmation.activate_app2_fa_token = Set(None);
        user_confirmation.activate_app2_fa_token_expiry = Set(None);

        let mut user_security_settings = user_security_settings.into_active_model();
        user_security_settings.two_factor_authenticator_app = Set(enable);
        user_security_settings.updated_at = Set(update_time.naive_utc());

        update_model(
            &txn,
            user_confirmation,
            "Failed to clear app 2FA activation token",
        )
        .await?;

        update_model(
            &txn,
            user_security_settings,
            "Failed to update app 2FA setting",
        )
        .await?;

        commit_transaction(txn).await?;

        Ok(())
    }

    async fn get_token_for_disable_app_2fa(
        &self,
        user: &UserId,
    ) -> Result<ConfirmDisableApp2FA, DomainError> {
        let (user_confirmation, user_credentials) =
            self.fetch_user_confirmation_and_credentials(&user).await?;

        let token_hash = user_confirmation.remove_user_token_hash.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing remove user token hash".to_string(),
            ))
        })?;

        let expiry = user_confirmation
            .activate_user_token_expiry
            .ok_or_else(|| {
                DomainError::PersistenceError(PersistenceError::Retrieve(
                    "Missing token expiry date".to_string(),
                ))
            })?;

        let expiry_utc = Utc.from_utc_datetime(&expiry);

        let secret = user_credentials.totp_secret.ok_or_else(|| {
            DomainError::PersistenceError(PersistenceError::Retrieve(
                "Missing secret in user security settings".to_string(),
            ))
        })?;

        Ok(ConfirmDisableApp2FA {
            token_hash,
            secret,
            expiry: expiry_utc,
        })
    }

    async fn remove_app_2fa_secret(&self, user_id: &UserId) -> Result<(), DomainError> {
        let mut user_credentials = fetch_user_credentials(&self.db, &user_id)
            .await?
            .into_active_model();
        user_credentials.totp_secret = Set(None);

        user_credentials
            .update(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Update(e.to_string())))?;

        Ok(())
    }

    async fn store_token_for_remove_user(
        &self,
        user: UserId,
        token_hash: String,
        expiry: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let mut confirmation = fetch_user_confirmation(&self.db, &user)
            .await?
            .into_active_model();
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
        let confirmation = fetch_user_confirmation(&self.db, &user).await?;

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
        let txn = begin_transaction(&self.db).await?;

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

        commit_transaction(txn).await?;

        Ok(())
    }
}

impl SeaOrmUserSecurityRepository {
    async fn fetch_user_confirmation_and_security(
        &self,
        user_id: &UserId,
    ) -> Result<(user_confirmation::Model, user_security_settings::Model), DomainError> {
        let user_confirmation_future = fetch_user_confirmation(&self.db, &user_id);
        let user_security_settings_future = fetch_user_security_settings(&self.db, &user_id);
        let (user_confirmation_result, user_security_settings_result) =
            tokio::join!(user_confirmation_future, user_security_settings_future);
        let user_confirmation = user_confirmation_result?;
        let user_security_settings = user_security_settings_result?;
        Ok((user_confirmation, user_security_settings))
    }

    async fn fetch_user_confirmation_and_credentials(
        &self,
        user_id: &UserId,
    ) -> Result<(user_confirmation::Model, user_credentials::Model), DomainError> {
        let user_confirmation_future = fetch_user_confirmation(&self.db, &user_id);
        let user_credentials_future = fetch_user_credentials(&self.db, &user_id);
        let (user_confirmation_result, user_credentials_result) =
            tokio::join!(user_confirmation_future, user_credentials_future);
        let user_confirmation = user_confirmation_result?;
        let user_credentials = user_credentials_result?;
        Ok((user_confirmation, user_credentials))
    }
}
