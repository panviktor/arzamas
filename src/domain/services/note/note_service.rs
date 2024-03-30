use crate::application::dto::shared::paginated_result::PaginatedResult;
use crate::domain::entities::note::Note;
use crate::domain::error::DomainError;
use crate::domain::repositories::note::note_parameters::{FindNote, FindNotes, UpdateNote};
use crate::domain::repositories::note::note_repository::NoteDomainRepository;

pub struct NoteDomainService<R: NoteDomainRepository> {
    note_repository: R,
}

impl<R: NoteDomainRepository> NoteDomainService<R> {
    pub fn new(note_repository: R) -> Self {
        Self { note_repository }
    }

    pub async fn add_note(&self, note: Note) -> Result<Note, DomainError> {
        self.note_repository.add_note(note).await
    }

    pub async fn find_one(&self, note: FindNote) -> Result<Note, DomainError> {
        self.note_repository.find_one(note).await
    }

    pub async fn find_all(&self, note: FindNotes) -> Result<PaginatedResult<Note>, DomainError> {
        self.note_repository.find_all(note).await
    }

    pub async fn update(&self, note: UpdateNote) -> Result<Note, DomainError> {
        self.note_repository.update(note).await
    }

    pub async fn delete(&self, note: FindNote) -> Result<(), DomainError> {
        self.note_repository.delete(note).await
    }
}
