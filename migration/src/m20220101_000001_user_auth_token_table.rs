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
                    .table(UserAuthToken::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserAuthToken::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserAuthToken::UserId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_otp_token_user_id")
                            .from(UserAuthToken::Table, UserAuthToken::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(UserAuthToken::OtpPublicToken)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserAuthToken::OtpEmailCodeHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserAuthToken::OtpEmailCurrentlyValid)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(UserAuthToken::OtpAppHash).string().null())
                    .col(
                        ColumnDef::new(UserAuthToken::OtpAppCurrentlyValid)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserAuthToken::OtpAppMnemonic)
                            .string()
                            .null(),
                    )
                    .col(ColumnDef::new(UserAuthToken::Expiry).timestamp().null())
                    .col(
                        ColumnDef::new(UserAuthToken::AttemptCount)
                            .big_unsigned()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(UserAuthToken::UserAgent).string().null())
                    .col(ColumnDef::new(UserAuthToken::IpAddress).string().null())
                    .col(
                        ColumnDef::new(UserAuthToken::LongSession)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .drop_table(Table::drop().table(UserAuthToken::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum UserAuthToken {
    Table,
    Id,
    UserId,
    OtpPublicToken,
    OtpEmailCodeHash,
    OtpEmailCurrentlyValid,
    OtpAppHash,
    OtpAppCurrentlyValid,
    OtpAppMnemonic,
    Expiry,
    AttemptCount,
    UserAgent,
    IpAddress,
    LongSession,
}
