use crate::domain::entities::note::{NoteError, NoteText};

pub struct NoteValidationService;

impl NoteValidationService {
    pub fn validate_text(text: &NoteText) -> Result<(), NoteError> {
        if text.value().trim().is_empty() {
            return Err(NoteError::InvalidNoteText(
                "Note text cannot be empty.".into(),
            ));
        }
        Ok(())
    }
}
