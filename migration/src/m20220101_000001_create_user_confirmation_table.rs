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
                    .table(UserConfirmation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserConfirmation::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::UserId)
                            .string()
                            .not_null()
                            .unique_key()
                    )
                    .col(ColumnDef::new(UserConfirmation::Email).string().not_null())
                    .col(ColumnDef::new(UserConfirmation::OTPHash).string().not_null())
                    .col(ColumnDef::new(UserConfirmation::Expiry).timestamp().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .drop_table(Table::drop().table(UserConfirmation::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum UserConfirmation {
    Id,
    Table,
    UserId,
    Email,
    OTPHash,
    Expiry,
}
