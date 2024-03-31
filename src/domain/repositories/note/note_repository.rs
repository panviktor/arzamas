use crate::application::dto::shared::paginated_result::PaginatedResult;
use crate::domain::entities::note::Note;
use crate::domain::error::DomainError;
use crate::domain::repositories::note::note_parameters::{
    CreateNoteDTO, FindNoteDTO, FindNotesDTO, UpdateNoteDTO,
};
use async_trait::async_trait;

#[async_trait]
pub trait NoteDomainRepository {
    /// Insert the received entity in the persistence system
    async fn add_note(&self, note: Note) -> Result<Note, DomainError>;

    /// Find and return one single record from the persistence system
    async fn find_one(&self, note: FindNoteDTO) -> Result<Note, DomainError>;

    /// Find and return all records corresponding to the search criteria from the persistence system
    async fn find_all(&self, notes: FindNotesDTO) -> Result<PaginatedResult<Note>, DomainError>;

    /// Update one single record already present in the persistence system
    async fn update(&self, note: UpdateNoteDTO) -> Result<Note, DomainError>;

    /// Delete one single record from the persistence system
    async fn delete(&self, note: FindNoteDTO) -> Result<(), DomainError>;
}
