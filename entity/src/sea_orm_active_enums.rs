//! `SeaORM` Entity. Generated by sea-orm-codegen 0.10.6

use sea_orm::entity::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "two_factor_method")]
pub enum TwoFactorMethod {
    #[sea_orm(string_value = "authenticator_app")]
    AuthenticatorApp,
    #[sea_orm(string_value = "email")]
    Email,
}
