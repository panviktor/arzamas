use crate::domain::entities::note::Note;
use crate::domain::entities::shared::value_objects::DomainPage;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::ports::repositories::note::note_parameters::{
    FindNoteDTO, FindNotesDTO, UpdateNoteDTO,
};
use crate::domain::ports::repositories::note::note_repository::NoteDomainRepository;
use crate::infrastructure::repository::fetch_model;
use async_trait::async_trait;
use chrono::Utc;
use entity::note;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, IntoActiveModel, ModelTrait,
    PaginatorTrait, QueryFilter, Set,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct SeaOrmNoteRepository {
    db: Arc<DatabaseConnection>,
}

impl SeaOrmNoteRepository {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl NoteDomainRepository for SeaOrmNoteRepository {
    async fn add_note(&self, note: Note) -> Result<Note, DomainError> {
        let active_model = note.into_active_model();
        let res = active_model
            .insert(&*self.db)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        Ok(res.into())
    }

    async fn find_one(&self, note: FindNoteDTO) -> Result<Note, DomainError> {
        let note_model = fetch_model::<note::Entity>(
            &self.db,
            note::Column::UserId
                .eq(note.user_id)
                .and(note::Column::NoteId.eq(note.note_id.clone())),
            "Note not found",
        )
        .await?;

        Ok(note_model.into())
    }

    async fn find_all(&self, notes: FindNotesDTO) -> Result<DomainPage<Note>, DomainError> {
        let paginator = note::Entity::find()
            .filter(note::Column::UserId.eq(notes.user_id))
            .paginate(&*self.db, notes.per_page);

        let num_items_and_pages = paginator.num_items_and_pages().await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
        })?;

        let find_notes = paginator
            .fetch_page(notes.page.saturating_sub(1))
            .await
            .map_err(|e| {
                DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string()))
            })?;

        let domain_notes = find_notes.into_iter().map(Note::from).collect();

        let result = DomainPage {
            items: domain_notes,
            total_items: num_items_and_pages.number_of_items,
            total_pages: num_items_and_pages.number_of_pages,
        };

        Ok(result)
    }

    async fn update(&self, note: UpdateNoteDTO) -> Result<Note, DomainError> {
        let mut existing_note = fetch_model::<note::Entity>(
            &self.db,
            note::Column::NoteId
                .eq(&note.note_id)
                .and(note::Column::UserId.eq(&note.user_id)),
            &format!("Failed to find note {}", &note.note_id),
        )
        .await?
        .into_active_model();

        existing_note.text = Set(note.text.value().to_owned());
        existing_note.updated_at = Set(Utc::now().naive_utc());

        let updated_note = existing_note.update(&*self.db).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to update note {}: {}",
                &note.note_id, e
            )))
        })?;

        Ok(updated_note.into())
    }

    async fn delete(&self, note: FindNoteDTO) -> Result<(), DomainError> {
        let existing_note = fetch_model::<note::Entity>(
            &self.db,
            note::Column::UserId
                .eq(&note.user_id)
                .and(note::Column::NoteId.eq(&note.note_id)),
            &format!("Note not found with id {}", &note.note_id),
        )
        .await?;

        existing_note.delete(&*self.db).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Delete(format!(
                "Failed to delete note {}: {}",
                note.note_id, e
            )))
        })?;
        Ok(())
    }
}
