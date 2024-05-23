use crate::domain::entities::shared::value_objects::{IPAddress, UserAgent};
use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::user_otp_token::UserOtpToken;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::UserRegistration;
use crate::domain::error::{DomainError, ValidationError};
use chrono::{DateTime, TimeZone, Utc};
use entity::{user, user_otp_token, user_security_settings, user_session};
use sea_orm::ActiveValue::Set;

impl UserRegistration {
    pub fn into_active_model(self) -> user::ActiveModel {
        user::ActiveModel {
            user_id: Set(self.user_id),
            email: sea_orm::Set(self.email.into_inner()),
            username: sea_orm::Set(self.username.into_inner()),
            pass_hash: sea_orm::Set(self.pass_hash),
            created_at: sea_orm::Set(self.created_at.naive_utc()),
            updated_at: sea_orm::Set(self.created_at.naive_utc()),

            ..Default::default()
        }
    }
}

impl From<user::Model> for UserRegistration {
    fn from(model: user::Model) -> Self {
        let email = Email::try_from(model.email).expect("Invalid email");

        UserRegistration::new(
            model.user_id,
            email,
            Username(model.username),
            model.pass_hash,
            Utc.from_utc_datetime(&model.created_at),
        )
    }
}

impl TryFrom<user_otp_token::Model> for UserOtpToken {
    type Error = DomainError;

    fn try_from(model: user_otp_token::Model) -> Result<Self, Self::Error> {
        // Convert NaiveDateTime to DateTime<Utc> while retaining Option
        let otp_email_valid_time = model
            .otp_email_valid_time
            .map(|naive_dt| Utc.from_utc_datetime(&naive_dt));

        let otp_app_valid_time = model
            .otp_app_valid_time
            .map(|naive_dt| Utc.from_utc_datetime(&naive_dt));

        let expiry = model
            .expiry
            .map(|naive_dt| Utc.from_utc_datetime(&naive_dt));

        // Check for critical missing data
        let user_agent = model
            .user_agent
            .as_deref()
            .map(UserAgent::new)
            .ok_or_else(|| {
                DomainError::ValidationError(ValidationError::InvalidData(
                    "User agent missing".to_string(),
                ))
            })?;

        let ip_address = model
            .ip_address
            .as_deref() // Similarly handling Option<String>
            .map(IPAddress::new)
            .ok_or_else(|| {
                DomainError::ValidationError(ValidationError::InvalidData(
                    "IP address missing".to_string(),
                ))
            })?;

        Ok(UserOtpToken {
            user_id: model.user_id,
            otp_email_hash: model.otp_email_hash,
            otp_email_valid_time,
            otp_email_currently_valid: model.otp_email_currently_valid,
            otp_app_hash: model.otp_app_hash,
            otp_app_valid_time,
            otp_app_currently_valid: model.otp_app_currently_valid,
            otp_app_mnemonic: model.otp_app_mnemonic,
            expiry,
            attempt_count: model.attempt_count,
            user_agent,
            ip_address,
            persistent: model.long_session,
        })
    }
}

impl From<user_security_settings::Model> for UserSecuritySettings {
    fn from(model: user_security_settings::Model) -> UserSecuritySettings {
        UserSecuritySettings {
            user_id: model.user_id,
            two_factor_email: model.two_factor_email,
            two_factor_authenticator_app: model.two_factor_authenticator_app,
            totp_secret: model.totp_secret,
            email_on_success_enabled_at: model.email_on_success_enabled_at,
            email_on_failure_enabled_at: model.email_on_failure_enabled_at,
            close_sessions_on_change_password: model.close_sessions_on_change_password,
        }
    }
}

impl From<user_session::Model> for UserSession {
    fn from(model: user_session::Model) -> Self {
        let login_timestamp = Utc.from_utc_datetime(&model.login_timestamp);
        let user_agent = UserAgent::new(&model.user_agent);
        let ip_address = IPAddress::new(&model.ip_address);
        let expiry = Utc.from_utc_datetime(&model.expiry);

        UserSession::new(
            &model.user_id,
            &model.session_id,
            &model.session_name,
            login_timestamp,
            &user_agent,
            &ip_address,
            expiry,
        )
    }
}
