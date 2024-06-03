#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl EmailMessage {
    pub fn new(to: String, subject: String, body: String) -> Self {
        Self { to, subject, body }
    }
}
