#[derive(Debug, Clone)]
pub struct Email(pub String);

impl Email {
    pub fn value(&self) -> &String {
        &self.0
    }
}

impl Email {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for Email {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.is_empty() {
            Err("Email cannot be empty")
        } else {
            Ok(Self(text))
        }
    }
}
