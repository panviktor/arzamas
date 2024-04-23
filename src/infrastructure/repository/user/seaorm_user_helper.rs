use crate::domain::entities::shared::{Email, Username};
use crate::domain::entities::user::UserRegistration;
use chrono::{TimeZone, Utc};
use entity::user;
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
