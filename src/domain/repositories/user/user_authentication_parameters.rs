#[derive(Debug, Clone)]
pub struct CreateLoginRequestDTO {
    pub identifier: String,
    pub password: String,
    pub user_agent: String,
    pub ip_address: String,
    pub persistent: bool,
}

impl CreateLoginRequestDTO {
    pub fn new(
        identifier: String,
        password: String,
        user_agent: String,
        ip_address: String,
        persistent: bool,
    ) -> Self {
        Self {
            identifier,
            password,
            user_agent,
            ip_address,
            persistent,
        }
    }
}
