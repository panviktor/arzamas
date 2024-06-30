use crate::domain::entities::note::Note;
use chrono::{DateTime, Utc};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NoteResponse {
    note_id: String,
    user_id: String,
    text: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl NoteResponse {
    pub fn from(note: Note) -> Self {
        Self {
            note_id: note.note_id,
            user_id: note.user_id,
            text: note.text.into_inner(),
            created_at: note.created_at,
            updated_at: note.updated_at,
        }
    }
}
