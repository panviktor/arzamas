use super::m20220101_000001_user_table::User;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UserSession::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserSession::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserSession::SessionId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(ColumnDef::new(UserSession::UserId).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_session_assignee")
                            .from(UserSession::Table, UserSession::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(ColumnDef::new(UserSession::SessionName).string().not_null())
                    .col(
                        ColumnDef::new(UserSession::LoginTimestamp)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserSession::IpAddress).string().not_null())
                    .col(ColumnDef::new(UserSession::UserAgent).string().not_null())
                    .col(ColumnDef::new(UserSession::Expiry).timestamp().not_null())
                    .col(
                        ColumnDef::new(UserSession::Valid)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserSession::Table).to_owned())
            .await
    }
}
#[derive(Iden)]
enum UserSession {
    Table,
    Id,
    UserId,
    SessionId,
    SessionName,
    LoginTimestamp,
    IpAddress,
    UserAgent,
    Expiry,
    Valid,
}
