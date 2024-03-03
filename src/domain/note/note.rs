use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteText(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub(crate) note_id: String,
    pub(crate) user_id: String,
    pub(crate) text: NoteText,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
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
}

impl NoteText {
    pub fn value(&self) -> &String {
        &self.0
    }
}

impl TryFrom<String> for NoteText {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.is_empty() {
            Err("Note text cannot be empty")
        } else {
            Ok(Self(text))
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
