//! `SeaORM` Entity. Generated by sea-orm-codegen 0.10.6

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    #[sea_orm(unique)]
    pub user_id: String,
    pub email: String,
    pub username: String,
    pub pass_hash: String,
    pub email_validated: bool,
    pub totp_active: bool,
    pub totp_token: Option<String>,
    pub totp_backups: Option<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::note::Entity")]
    Note,
}

impl Related<super::note::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Note.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
