use super::m20220101_000000_user_table::User;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserCredentials::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserCredentials::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserCredentials::UserId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_credentials_assignee_user_id")
                            .from(UserCredentials::Table, UserCredentials::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(UserCredentials::PassHash)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserCredentials::EmailValidated)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(ColumnDef::new(UserCredentials::TotpSecret).string().null())
                    .col(
                        ColumnDef::new(UserCredentials::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserCredentials::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum UserCredentials {
    Table,
    Id,
    UserId,
    PassHash,
    EmailValidated,
    TotpSecret,
    UpdatedAt,
}
