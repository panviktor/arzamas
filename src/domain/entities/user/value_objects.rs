#[derive(Debug, Clone)]
pub struct UserIdentifier(pub String);

impl UserIdentifier {
    pub fn value(&self) -> &String {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for UserIdentifier {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.trim().is_empty() {
            Err("Invalid username format.")
        } else {
            Ok(Self(text))
        }
    }
}
