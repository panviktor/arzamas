pub use sea_orm_migration::prelude::*;

mod m20220101_000001_user_confirmation_table;
mod m20220101_000001_user_notes_table;
mod m20220101_000001_user_otp_token_table;
mod m20220101_000001_user_restore_password_table;
mod m20220101_000001_user_security_setting_table;
mod m20220101_000001_user_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_user_table::Migration),
            Box::new(m20220101_000001_user_confirmation_table::Migration),
            Box::new(m20220101_000001_user_notes_table::Migration),
            Box::new(m20220101_000001_user_restore_password_table::Migration),
            Box::new(m20220101_000001_user_otp_token_table::Migration),
            Box::new(m20220101_000001_user_security_setting_table::Migration),
        ]
    }
}
