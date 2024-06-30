use crate::domain::entities::note::Note;
use crate::domain::entities::shared::value_objects::DomainPage;
use crate::domain::error::DomainError;
use crate::domain::ports::repositories::note::note_parameters::{
    CreateNoteDTO, FindNoteDTO, FindNotesDTO, UpdateNoteDTO,
};
use crate::domain::ports::repositories::note::note_repository::NoteDomainRepository;

pub struct NoteDomainService<R: NoteDomainRepository> {
    note_repository: R,
}

impl<R: NoteDomainRepository> NoteDomainService<R> {
    pub fn new(note_repository: R) -> Self {
        Self { note_repository }
    }

    pub async fn add_note(&self, note: CreateNoteDTO) -> Result<Note, DomainError> {
        let note = Note::create(note.user_id, note.text)?;
        self.note_repository.add_note(note).await
    }

    pub async fn find_one(&self, note: FindNoteDTO) -> Result<Note, DomainError> {
        self.note_repository.find_one(note).await
    }

    pub async fn find_all(&self, note: FindNotesDTO) -> Result<DomainPage<Note>, DomainError> {
        self.note_repository.find_all(note).await
    }

    pub async fn update(&self, note: UpdateNoteDTO) -> Result<Note, DomainError> {
        self.note_repository.update(note).await
    }

    pub async fn delete(&self, note: FindNoteDTO) -> Result<(), DomainError> {
        self.note_repository.delete(note).await
    }
}
