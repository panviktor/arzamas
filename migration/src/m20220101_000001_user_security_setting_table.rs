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
                    .table(UserSecuritySettings::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserSecuritySettings::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::UserId)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_security_settings_user_id")
                            .from(UserSecuritySettings::Table, UserSecuritySettings::UserId)
                            .to(User::Table, User::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::TwoFactorEmail)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::TwoFactorAuthenticatorApp)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::EmailOnSuccessEnabledAt)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::EmailOnFailureEnabledAt)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::CloseSessionsOnChangePassword)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserSecuritySettings::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum UserSecuritySettings {
    Id,
    Table,
    UserId,
    TwoFactorEmail,
    TwoFactorAuthenticatorApp,
    EmailOnSuccessEnabledAt,
    EmailOnFailureEnabledAt,
    CloseSessionsOnChangePassword,
    UpdatedAt,
}
