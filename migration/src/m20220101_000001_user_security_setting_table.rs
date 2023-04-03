use entity::{user, user_security_settings};
use sea_orm::{sea_query::extension::postgres::Type, EnumIter};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_type(
                Type::create()
                    .as_enum(TwoFactorMethod::Table)
                    .values([TwoFactorMethod::Email, TwoFactorMethod::AuthenticatorApp])
                    .to_owned(),
            )
            .await?;

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
                            .name("fk_security_settings_assignee")
                            .from(
                                user_security_settings::Entity,
                                user_security_settings::Column::UserId,
                            )
                            .to(user::Entity, user::Column::UserId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::TwoFactorMethod)
                            .enumeration(
                                TwoFactorMethod::Table,
                                [TwoFactorMethod::Email, TwoFactorMethod::AuthenticatorApp],
                            )
                            .null(),
                    )
                    .col(
                        ColumnDef::new(UserSecuritySettings::TotpSecret)
                            .string()
                            .null(),
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
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserSecuritySettings::Table).to_owned())
            .await?;

        manager
            .drop_type(Type::drop().name(TwoFactorMethod::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum UserSecuritySettings {
    Id,
    Table,
    UserId,
    TwoFactorMethod,
    TotpSecret,
    EmailOnSuccessEnabledAt,
    EmailOnFailureEnabledAt,
    CloseSessionsOnChangePassword,
}

#[derive(Iden, EnumIter)]
enum TwoFactorMethod {
    Table,
    Email,
    AuthenticatorApp,
}
