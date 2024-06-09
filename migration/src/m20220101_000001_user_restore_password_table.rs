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
                    .table(UserRestorePassword::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserRestorePassword::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserRestorePassword::UserId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_restore_password_user_id")
                            .from(UserRestorePassword::Table, UserRestorePassword::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(ColumnDef::new(UserRestorePassword::OTPHash).string().null())
                    .col(
                        ColumnDef::new(UserRestorePassword::Expiry)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserRestorePassword::UserAgent)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserRestorePassword::IpAddress)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserRestorePassword::AttemptCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(UserRestorePassword::RestoreBlockedUntil)
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
            .drop_table(Table::drop().table(UserRestorePassword::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum UserRestorePassword {
    Id,
    Table,
    UserId,
    OTPHash,
    UserAgent,
    IpAddress,
    Expiry,
    AttemptCount,
    RestoreBlockedUntil,
}
