#[derive(Debug, Clone)]
pub struct UserIdentifier {
    pub identifier: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

impl UserIdentifier {
    pub fn new(identifier: String, user_agent: Option<String>, ip_address: Option<String>) -> Self {
        Self {
            identifier,
            user_agent,
            ip_address,
        }
    }

    pub fn value(&self) -> &str {
        &self.identifier
    }

    // Optional getters for user_agent and ip_address
    pub fn user_agent(&self) -> Option<&String> {
        self.user_agent.as_ref()
    }

    pub fn ip_address(&self) -> Option<&String> {
        self.ip_address.as_ref()
    }
}

impl TryFrom<String> for UserIdentifier {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.trim().is_empty() {
            Err("Identifier cannot be empty.")
        } else {
            // Assuming default None values for optional fields when converting from String
            Ok(Self::new(text, None, None))
        }
    }
}
