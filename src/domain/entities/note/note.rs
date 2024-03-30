use crate::domain::entities::note::NoteText;
use crate::domain::error::{DomainError, ValidationError};
use crate::domain::services::note::note_validation_service::NoteValidationService;
use crate::domain::services::shared::SharedDomainService;
use chrono::{DateTime, Utc};
use std::fmt;

#[derive(Debug, Clone)]
pub struct Note {
    pub note_id: String,
    pub user_id: String,
    pub text: NoteText,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
pub enum NoteError {
    InvalidNoteText(String),
}

impl Note {
    pub fn new(
        note_id: String,
        user_id: String,
        text: NoteText,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            note_id,
            user_id,
            text,
            created_at,
            updated_at,
        }
    }

    pub fn create(user_id: String, text: NoteText) -> Result<Self, NoteError> {
        NoteValidationService::validate_text(&text)?;
        let now = Utc::now();
        let note_id = SharedDomainService::generate_unique_id();
        Ok(Note::new(note_id, user_id, text, now, now))
    }
}

impl From<NoteError> for DomainError {
    fn from(error: NoteError) -> Self {
        match error {
            NoteError::InvalidNoteText(msg) => {
                DomainError::ValidationError(ValidationError::InvalidData(msg))
            }
        }
    }
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Note ID: {}, User ID: {}, Text: {}, Created At: {}, Updated At: {}",
            self.note_id,
            self.user_id,
            self.text.value(),
            self.created_at,
            self.updated_at
        )
    }
}
