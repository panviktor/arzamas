use crate::application::dto::shared::paginated_result::PaginatedResult;
use crate::domain::entities::note::Note;
use crate::domain::error::{DomainError, PersistenceError};
use crate::domain::repositories::note::note_parameters::{FindNote, FindNotes, UpdateNote};
use crate::domain::repositories::note::note_repository::NoteDomainRepository;
use async_trait::async_trait;
use chrono::Utc;
use entity::note;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, PaginatorTrait,
    QueryFilter, Set,
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
        let db_ref = Arc::as_ref(&self.db);
        let active_model = note.into_active_model();
        let res = active_model
            .insert(db_ref)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Create(e.to_string())))?;

        Ok(res.into())
    }

    async fn find_one(&self, note: FindNote) -> Result<Note, DomainError> {
        let db_ref = Arc::as_ref(&self.db);

        let note_model = note::Entity::find()
            .filter(note::Column::UserId.eq(note.user_id))
            .filter(note::Column::NoteId.eq(&note.note_id))
            .one(db_ref)
            .await
            .map_err(|e| DomainError::PersistenceError(PersistenceError::Retrieve(e.to_string())))?
            .ok_or_else(|| DomainError::NotFound)?;

        Ok(note_model.into())
    }

    async fn find_all(&self, notes: FindNotes) -> Result<PaginatedResult<Note>, DomainError> {
        let db_ref = Arc::as_ref(&self.db);

        let paginator = note::Entity::find()
            .filter(note::Column::UserId.eq(notes.user_id))
            .paginate(db_ref, notes.per_page);

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

        let result = PaginatedResult {
            items: domain_notes,
            total_items: num_items_and_pages.number_of_items,
            total_pages: num_items_and_pages.number_of_pages,
            current_page: notes.page,
            items_per_page: notes.per_page,
        };

        Ok(result)
    }

    async fn update(&self, note: UpdateNote) -> Result<Note, DomainError> {
        let db_ref = Arc::as_ref(&self.db);

        let existing_note = note::Entity::find()
            .filter(note::Column::NoteId.eq(&note.note_id))
            .filter(note::Column::UserId.eq(&note.user_id))
            .one(db_ref)
            .await
            .map_err(|_| {
                DomainError::PersistenceError(PersistenceError::Retrieve(format!(
                    "Failed to find note {}.",
                    &note.note_id
                )))
            })?
            .ok_or_else(|| DomainError::NotFound)?;

        let mut active: note::ActiveModel = existing_note.into();
        active.text = Set(note.text.value().to_owned());
        active.updated_at = Set(Utc::now().naive_utc());

        let updated_note = active.update(db_ref).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Update(format!(
                "Failed to update note {}: {}",
                &note.note_id, e
            )))
        })?;

        Ok(updated_note.into())
    }

    async fn delete(&self, note: FindNote) -> Result<(), DomainError> {
        let db_ref = Arc::as_ref(&self.db);

        let existing_note = note::Entity::find()
            .filter(note::Column::UserId.eq(&note.user_id))
            .filter(note::Column::NoteId.eq(&note.note_id))
            .one(db_ref)
            .await
            .map_err(|_| {
                DomainError::PersistenceError(PersistenceError::Delete(
                    "Database error occurred".to_string(),
                ))
            })?
            .ok_or_else(|| DomainError::NotFound)?;

        existing_note.delete(db_ref).await.map_err(|e| {
            DomainError::PersistenceError(PersistenceError::Delete(format!(
                "Failed to delete note {}: {}",
                note.note_id, e
            )))
        })?;
        Ok(())
    }
}
