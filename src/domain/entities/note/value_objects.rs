#[derive(Debug, Clone)]
pub struct NoteText(pub String);

impl NoteText {
    pub fn value(&self) -> &String {
        &self.0
    }
}

impl NoteText {
    pub fn into_inner(self) -> String {
        self.0
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
