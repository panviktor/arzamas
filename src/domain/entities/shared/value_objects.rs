use std::fmt;

/// Email
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

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}
impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Username

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

/// EmailToken

#[derive(Clone, Debug)]
pub struct OtpToken(pub String);
impl OtpToken {
    pub fn new(token: &str) -> Self {
        Self(token.to_string())
    }
    pub fn value(&self) -> &String {
        &self.0
    }
}
impl OtpToken {
    pub fn into_inner(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct OtpCode(pub String);
impl OtpCode {
    pub fn new(token: &str) -> Self {
        Self(token.to_string())
    }
    pub fn value(&self) -> &String {
        &self.0
    }
}

/// UserAgent

#[derive(Clone, Debug)]
pub struct UserAgent(pub String);

impl UserAgent {
    pub fn new(user_agent: &str) -> Self {
        Self(user_agent.to_string())
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl PartialEq for UserAgent {
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

/// IPAddress
#[derive(Clone, Debug)]
pub struct IPAddress(pub String);

impl IPAddress {
    pub fn new(ip_address: &str) -> Self {
        Self(ip_address.to_string())
    }

    pub fn value(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl PartialEq for IPAddress {
    fn eq(&self, other: &Self) -> bool {
        self.value() == other.value()
    }
}

pub struct DomainPage<T> {
    pub items: Vec<T>,
    pub total_items: u64,
    pub total_pages: u64,
}

#[derive(Clone, Debug)]
pub struct UserId {
    pub user_id: String,
}

impl UserId {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
        }
    }
}
