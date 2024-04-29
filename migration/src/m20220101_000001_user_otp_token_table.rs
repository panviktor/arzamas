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
                    .table(UserOTPToken::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserOTPToken::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserOTPToken::UserId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_otp_token_user_id")
                            .from(UserOTPToken::Table, UserOTPToken::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(ColumnDef::new(UserOTPToken::OtpEmailHash).string().null())
                    .col(
                        ColumnDef::new(UserOTPToken::OtpEmailValidTime)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserOTPToken::OtpEmailCurrentlyValid)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(UserOTPToken::OtpAppHash).string().null())
                    .col(
                        ColumnDef::new(UserOTPToken::OtpAppValidTime)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserOTPToken::OtpAppCurrentlyValid)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(UserOTPToken::OtpAppMnemonic).string().null())
                    .col(ColumnDef::new(UserOTPToken::Expiry).timestamp().null())
                    .col(
                        ColumnDef::new(UserOTPToken::AttemptCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(UserOTPToken::UserAgent).string().null())
                    .col(ColumnDef::new(UserOTPToken::IpAddress).string().null())
                    .col(
                        ColumnDef::new(UserOTPToken::LongSession)
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
            .drop_table(Table::drop().table(UserOTPToken::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum UserOTPToken {
    Table,
    Id,
    UserId,
    OtpEmailHash,
    OtpEmailValidTime,
    OtpEmailCurrentlyValid,
    OtpAppHash,
    OtpAppValidTime,
    OtpAppCurrentlyValid,
    OtpAppMnemonic,
    Expiry,
    AttemptCount,
    UserAgent,
    IpAddress,
    LongSession,
}
