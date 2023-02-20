use sea_orm_migration::prelude::*;
use entity::{ note, user };


#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(Note::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Note::Id)
                            .big_integer()
                            .auto_increment()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Note::UserId)
                            .string()
                            .not_null()
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_note_assignee")
                            .from(note::Entity, note::Column::UserId)
                            .to(user::Entity, user::Column::UserId),
                    )
                    .col(
                        ColumnDef::new(Note::Text)
                            .string()
                            .not_null()
                    )
                    .col(ColumnDef::new(Note::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(Note::UpdatedAt).timestamp().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .drop_table(Table::drop().table(Note::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum Note {
    Id,
    Table,
    UserId,
    Text,
    CreatedAt,
    UpdatedAt
}
