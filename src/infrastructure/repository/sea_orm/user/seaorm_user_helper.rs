use crate::domain::entities::shared::value_objects::{IPAddress, OtpCode, UserAgent};
use crate::domain::entities::shared::Email;
use crate::domain::entities::user::user_authentication::{UserAuthenticationData, UserCredentials};
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::UserBase;
use chrono::{TimeZone, Utc};
use entity::{user, user_authentication, user_credentials, user_security_settings, user_session};
use sea_orm::ActiveValue::Set;

impl From<user_authentication::Model> for UserAuthenticationData {
    fn from(model: user_authentication::Model) -> Self {
        let expiry = model
            .attempt_expiry
            .map(|naive_dt| Utc.from_utc_datetime(&naive_dt));

        let user_agent = model.user_agent.as_deref().map(UserAgent::new);
        let ip_address = model.ip_address.as_deref().map(IPAddress::new);

        UserAuthenticationData {
            otp_email_code_hash: model.otp_email_code_hash.as_deref().map(OtpCode::new),
            otp_email_currently_valid: model.otp_email_currently_valid,
            otp_app_currently_valid: model.otp_app_currently_valid,
            expiry,
            attempt_count: model.attempt_count,
            user_agent,
            ip_address,
            long_session: model.long_session,
            login_blocked_until: model
                .login_blocked_until
                .map(|naive_dt| Utc.from_utc_datetime(&naive_dt)),
        }
    }
}

impl From<user_security_settings::Model> for UserSecuritySettings {
    fn from(model: user_security_settings::Model) -> UserSecuritySettings {
        UserSecuritySettings {
            two_factor_email: model.two_factor_email,
            two_factor_authenticator_app: model.two_factor_authenticator_app,
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
            model.valid,
        )
    }
}

impl UserSession {
    pub fn into_active_model(self) -> user_session::ActiveModel {
        user_session::ActiveModel {
            session_id: Set(self.session_id),
            user_id: Set(self.user_id),
            session_name: Set(self.session_name),
            login_timestamp: Set(self.login_timestamp.naive_utc()),
            user_agent: Set(self.user_agent.value().to_string()),
            ip_address: Set(self.ip_address.value().to_string()),
            expiry: Set(self.expiry.naive_utc()),
            ..Default::default()
        }
    }
}

impl From<user::Model> for UserBase {
    fn from(user: user::Model) -> Self {
        UserBase {
            user_id: user.user_id,
            email: Email::new(&user.email),
            username: user.username,
            created_at: Utc.from_utc_datetime(&user.created_at),
            updated_at: Utc.from_utc_datetime(&user.updated_at),
        }
    }
}

impl From<user_credentials::Model> for UserCredentials {
    fn from(user: user_credentials::Model) -> Self {
        UserCredentials {
            pass_hash: user.pass_hash,
            email_validated: user.email_validated,
            totp_secret: user.totp_secret,
        }
    }
}
