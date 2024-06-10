use super::m20220101_000001_user_table::User;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(UserRecoveryPassword::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserRecoveryPassword::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserRecoveryPassword::UserId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_restore_password_user_id")
                            .from(UserRecoveryPassword::Table, UserRecoveryPassword::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(UserRecoveryPassword::RecoveryToken)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserRecoveryPassword::Expiry)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserRecoveryPassword::UserAgent)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserRecoveryPassword::IpAddress)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserRecoveryPassword::AttemptCount)
                            .big_unsigned()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(UserRecoveryPassword::RestoreBlockedUntil)
                            .timestamp()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .drop_table(Table::drop().table(UserRecoveryPassword::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum UserRecoveryPassword {
    Id,
    Table,
    UserId,
    RecoveryToken,
    UserAgent,
    IpAddress,
    Expiry,
    AttemptCount,
    RestoreBlockedUntil,
}
