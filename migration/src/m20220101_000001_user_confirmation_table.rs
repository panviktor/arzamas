use crate::m20220101_000001_user_table::User;
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
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_confirmation_user_id")
                            .from(UserConfirmation::Table, UserConfirmation::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(ColumnDef::new(UserConfirmation::OTPHash).string().null())
                    .col(ColumnDef::new(UserConfirmation::Expiry).timestamp().null())
                    .col(ColumnDef::new(UserConfirmation::NewEmail).string().null())
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
    OTPHash,
    Expiry,
    NewEmail,
}
