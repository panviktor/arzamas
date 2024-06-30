use crate::domain::error::DomainError;

#[async_trait::async_trait]
pub trait EmailPort {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), DomainError>;
    async fn send_email_with_attachment(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        attachment_data: Vec<u8>,
        attachment_name: &str,
    ) -> Result<(), DomainError>;
}
