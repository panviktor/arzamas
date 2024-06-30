use super::m20220101_000000_user_table::User;
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
                    .table(UserAuthentication::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserAuthentication::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::UserId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_authentication_user_id")
                            .from(UserAuthentication::Table, UserAuthentication::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::OtpPublicToken)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::OtpEmailCodeHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::OtpEmailCurrentlyValid)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::OtpAppCurrentlyValid)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::AttemptExpiry)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::AttemptCount)
                            .big_unsigned()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::UserAgent)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::IpAddress)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::LongSession)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserAuthentication::LoginBlockedUntil)
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
            .drop_table(Table::drop().table(UserAuthentication::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum UserAuthentication {
    Table,
    Id,
    UserId,
    OtpPublicToken,
    OtpEmailCodeHash,
    OtpEmailCurrentlyValid,
    OtpAppCurrentlyValid,
    AttemptExpiry,
    AttemptCount,
    UserAgent,
    IpAddress,
    LongSession,
    LoginBlockedUntil,
}
