use crate::domain::entities::shared::value_objects::{IPAddress, OtpCode, UserAgent};
use crate::domain::entities::shared::{Email, OtpToken, Username};
use crate::domain::entities::user::user_authentication::UserAuthenticationData;
use crate::domain::entities::user::user_security_settings::UserSecuritySettings;
use crate::domain::entities::user::user_sessions::UserSession;
use crate::domain::entities::user::{UserBase, UserRegistration};
use chrono::{TimeZone, Utc};
use entity::{user, user_authentication, user_security_settings, user_session};
use sea_orm::ActiveValue::Set;

impl UserRegistration {
    pub fn into_active_model(self) -> user::ActiveModel {
        user::ActiveModel {
            user_id: Set(self.user_id),
            email: Set(self.email.into_inner()),
            username: Set(self.username.into_inner()),
            pass_hash: Set(self.pass_hash),
            created_at: Set(self.created_at.naive_utc()),
            updated_at: Set(self.created_at.naive_utc()),

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

impl UserAuthenticationData {
    pub fn from_model(model: user_authentication::Model, email: Email) -> Self {
        let expiry = model
            .expiry
            .map(|naive_dt| Utc.from_utc_datetime(&naive_dt));

        let user_agent = model.user_agent.as_deref().map(UserAgent::new);
        let ip_address = model.ip_address.as_deref().map(IPAddress::new);

        UserAuthenticationData {
            user_id: model.user_id,
            email,
            otp_public_token: model.otp_public_token.as_deref().map(OtpToken::new),
            otp_email_code_hash: model.otp_email_code_hash.as_deref().map(OtpCode::new),
            otp_email_currently_valid: model.otp_email_currently_valid,
            otp_app_hash: model.otp_app_hash,
            otp_app_currently_valid: model.otp_app_currently_valid,
            otp_app_mnemonic: model.otp_app_mnemonic,
            expiry,
            attempt_count: model.attempt_count,
            user_agent,
            ip_address,
            long_session: model.long_session,
        }
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
            email_validated: user.email_validated,
            created_at: Utc.from_utc_datetime(&user.created_at),
            updated_at: Utc.from_utc_datetime(&user.updated_at),
        }
    }
}
