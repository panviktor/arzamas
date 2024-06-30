use crate::application::error::error::ApplicationError;
use crate::domain::entities::note::NoteError;

pub mod note_request_dto;
pub mod note_response_dto;

impl From<NoteError> for ApplicationError {
    fn from(error: NoteError) -> Self {
        match error {
            NoteError::InvalidNoteText(msg) => ApplicationError::BadRequest(msg),
        }
    }
}
