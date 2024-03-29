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
                    .col(ColumnDef::new(UserOTPToken::OTPEmailHash).string().null())
                    .col(ColumnDef::new(UserOTPToken::OTPAppHash).string().null())
                    .col(ColumnDef::new(UserOTPToken::OTPAppMnemonic).string().null())
                    .col(ColumnDef::new(UserOTPToken::Expiry).timestamp().null())
                    .col(
                        ColumnDef::new(UserOTPToken::AttemptCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(UserOTPToken::Code).string().null())
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
    Id,
    Table,
    UserId,
    OTPEmailHash,
    OTPAppHash,
    OTPAppMnemonic,
    Expiry,
    AttemptCount,
    Code,
}
