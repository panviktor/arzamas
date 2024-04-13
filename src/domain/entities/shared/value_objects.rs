#[derive(Debug, Clone)]
pub struct Email(pub String);

impl Email {
    pub fn new(email: &str) -> Self {
        Self(email.to_string())
    }
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

#[derive(Debug, Clone)]
pub struct Username(pub String);

impl Username {
    pub fn new(username: &str) -> Self {
        Self(username.to_string())
    }
    pub fn value(&self) -> &String {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for Username {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.trim().is_empty() {
            Err("Invalid username format.")
        } else {
            Ok(Self(text))
        }
    }
}
