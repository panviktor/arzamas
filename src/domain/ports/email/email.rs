use crate::domain::entities::email::EmailError;

#[async_trait::async_trait]
pub trait EmailPort {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), EmailError>;
}
