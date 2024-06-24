use crate::m20220101_000000_user_table::User;
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
                    .col(
                        ColumnDef::new(UserConfirmation::ActivateUserTokenHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::ActivateUserTokenExpiry)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::NewMainEmail)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::ActivateEmail2FAToken)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::ActivateEmail2FATokenExpiry)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::ActivateApp2FAToken)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::ActivateApp2FATokenExpiry)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::RemoveUserTokenHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserConfirmation::RemoveUserTokenExpiry)
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
    ActivateUserTokenHash,
    ActivateUserTokenExpiry,
    NewMainEmail,
    ActivateEmail2FAToken,
    ActivateEmail2FATokenExpiry,
    ActivateApp2FAToken,
    ActivateApp2FATokenExpiry,
    RemoveUserTokenHash,
    RemoveUserTokenExpiry,
}
