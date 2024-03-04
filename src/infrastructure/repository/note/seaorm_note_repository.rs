use crate::domain::note::note::Note;
use crate::infrastructure::repository::note::{FindNote, FindNotes, Repository};
use crate::infrastructure::repository::error::{
    RepoCreateError, RepoDeleteError, RepoFindAllError, RepoSelectError, RepoUpdateError,
};
use async_trait::async_trait;
use chrono::Utc;
use entity::note;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, PaginatorTrait, QueryFilter, Set};
use crate::application::dto::paginated_result::PaginatedResult;

#[derive(Clone)]
pub struct SeaOrmNoteRepository {
    db: DatabaseConnection,
}

impl SeaOrmNoteRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Repository<Note> for SeaOrmNoteRepository {
    async fn create(&self, note: Note) -> Result<Note, RepoCreateError> {
        let db = &self.db;
        let active_model = note.into_active_model();
        let res = active_model.insert(db).await;
        match res {
            Ok(model) => Ok(model.into()),
            Err(e) => Err(RepoCreateError::Unknown(e.to_string())),
        }
    }

    async fn find_one(&self, find_note: FindNote) -> Result<Note, RepoSelectError> {
        let db = &self.db;

        let note_model = note::Entity::find()
            .filter(note::Column::UserId.eq(find_note.user_id))
            .filter(note::Column::NoteId.eq(&find_note.note_id))
            .one(db)
            .await
            .map_err(|e| RepoSelectError::Unknown(e.to_string()))?
            .ok_or(RepoSelectError::NotFound(find_note.note_id))?;

        Ok(note_model.into())
    }

    async fn find_all(&self, find_notes: FindNotes) -> Result<PaginatedResult<Note>, RepoFindAllError> {
        let db = &self.db;

        let paginator = note::Entity::find()
            .filter(note::Column::UserId.eq(find_notes.user_id))
            .paginate(db, find_notes.per_page);

        let num_items_and_pages = paginator.num_items_and_pages().await?;

        let notes = paginator
            .fetch_page(find_notes.page.saturating_sub(1))
            .await
            .map_err(|e| RepoFindAllError::Unknown(e.to_string()))?;

        let domain_notes = notes.into_iter().map(Note::from).collect();

        let result = PaginatedResult {
            items: domain_notes,
            total_items: num_items_and_pages.number_of_items,
            total_pages: num_items_and_pages.number_of_pages,
            current_page: find_notes.page,
            items_per_page: find_notes.per_page,
        };

        Ok(result)
    }

    async fn update(&self, note: Note) -> Result<Note, RepoUpdateError> {
        let db = &self.db;

        let existing_note = note::Entity::find()
            .filter(note::Column::NoteId.eq(&note.note_id))
            .filter(note::Column::UserId.eq(&note.user_id))
            .one(db)
            .await
            .map_err(|_| RepoUpdateError::NotFound(format!("Note {} not found.", &note.note_id)))?
            .ok_or(RepoUpdateError::NotFound(note.note_id.clone()))?;

        let mut active: note::ActiveModel = existing_note.into();
        active.text = Set(note.text.value().to_owned());
        active.updated_at = Set(Utc::now().naive_utc());

        let updated_note = active.update(db).await.map_err(|e| {
            RepoUpdateError::Unknown(format!("Failed to update note {}: {}", &note.note_id, e))
        })?;

        Ok(updated_note.into())
    }

    async fn delete(&self, note_id: &str, user_id: &str) -> Result<(), RepoDeleteError> {
        let db = &self.db;

        let existing_note = note::Entity::find()
            .filter(note::Column::Id.eq(note_id))
            .filter(note::Column::UserId.eq(user_id))
            .one(db)
            .await
            .map_err(|_| RepoDeleteError::Unknown("Database error occurred".to_string()))?
            .ok_or(RepoDeleteError::NotFound(note_id.to_string()))?;

        existing_note.delete(db).await.map_err(|e| {
            RepoDeleteError::Unknown(format!("Failed to delete note {}: {}", note_id, e))
        })?;
        Ok(())
    }
}
