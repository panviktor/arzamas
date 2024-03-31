use crate::domain::entities::note::NoteText;

pub struct CreateNoteDTO {
    pub user_id: String,
    pub text: NoteText,
}

impl CreateNoteDTO {
    pub fn new(user_id: String, text: NoteText) -> Self {
        Self { user_id, text }
    }
}

#[derive(Debug, Clone)]
pub struct FindNoteDTO {
    pub user_id: String,
    pub note_id: String,
}

#[derive(Debug, Clone)]
pub struct UpdateNoteDTO {
    pub user_id: String,
    pub note_id: String,
    pub text: NoteText,
}

#[derive(Debug, Clone)]
pub struct FindNotesDTO {
    pub user_id: String,
    pub page: u64,
    pub per_page: u64,
}
