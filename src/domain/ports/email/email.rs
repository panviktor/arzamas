use crate::core::config::get_config;
use crate::domain::error::{DomainError, ExternalServiceError};
use crate::infrastructure::email::error::EmailError;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, MultiPart, SinglePart};
use lettre::Message;
use std::format;

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
