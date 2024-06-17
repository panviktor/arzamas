use crate::m20220101_000001_user_confirmation_table::UserConfirmation;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(UserConfirmation::Table)
                    .add_column(ColumnDef::new(UserConfirmation::NewEmail).string().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(UserConfirmation::Table)
                    .drop_column(UserConfirmation::NewEmail)
                    .to_owned(),
            )
            .await
    }
}
