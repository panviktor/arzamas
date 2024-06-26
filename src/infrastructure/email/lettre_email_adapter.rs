use crate::core::config::get_config;
use crate::domain::error::{DomainError, ExternalServiceError};
use crate::domain::ports::email::email::EmailPort;
use crate::infrastructure::email::error::EmailError;
use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use mime_guess::get_mime_extensions_str;
use secrecy::ExposeSecret;

pub struct LettreEmailAdapter {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl LettreEmailAdapter {
    pub fn new(mailer: AsyncSmtpTransport<Tokio1Executor>) -> Self {
        Self { mailer }
    }
}

#[async_trait]
impl EmailPort for LettreEmailAdapter {
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), DomainError> {
        let config = get_config().expect("Failed to read configuration.");
        let from = config.email_settings.email_from;

        let email = Message::builder()
            .from(format!("Sender <{}>", from).parse().unwrap())
            .to(format!("Receiver <{}>", to).parse().unwrap())
            .subject(subject)
            .body(body.to_string())
            .map_err(|_| EmailError::SendingFailed {
                message: "Failed to build email message".to_string(),
                recipient: to.to_string(),
                error_code: None,
            })?;

        self.mailer
            .send(email)
            .await
            .map_err(|e| EmailError::SendingFailed {
                message: format!("Email sending failed: {}", e),
                recipient: to.to_string(),
                error_code: None,
            })?;

        Ok(())
    }

    async fn send_email_with_attachment(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        attachment_data: Vec<u8>,
        attachment_name: &str,
    ) -> Result<(), DomainError> {
        let config = get_config().expect("Failed to read configuration.");
        let from = config.email_settings.email_from;

        // Get the MIME type of the attachment
        let mime_type = mime_guess::from_path(attachment_name).first_or_octet_stream();
        let content_type = ContentType::parse(mime_type.as_ref()).map_err(|_| {
            DomainError::ExternalServiceError(ExternalServiceError::Custom(format!(
                "Failed to parse MIME type: {}",
                mime_type
            )))
        })?;

        let extension = Self::get_file_extension(mime_type.as_ref()).unwrap_or("bin");

        // Construct the email with an attachment
        let email = Message::builder()
            .from(format!("Sender <{}>", from).parse().unwrap())
            .to(format!("Receiver <{}>", to).parse().unwrap())
            .subject(subject)
            .multipart(
                MultiPart::mixed()
                    .singlepart(SinglePart::plain(body.to_string()))
                    .singlepart(
                        Attachment::new(format!("{}.{}", attachment_name, extension))
                            .body(attachment_data, content_type),
                    ),
            )
            .map_err(|_| EmailError::SendingFailed {
                message: "Failed to build email message".to_string(),
                recipient: to.to_string(),
                error_code: None,
            })?;

        self.mailer
            .send(email)
            .await
            .map_err(|e| EmailError::SendingFailed {
                message: format!("Email sending failed: {}", e),
                recipient: to.to_string(),
                error_code: None,
            })?;

        Ok(())
    }
}

impl LettreEmailAdapter {
    fn get_file_extension(mime_type: &str) -> Option<&'static str> {
        let extensions = get_mime_extensions_str(mime_type)?;
        extensions.first().copied()
    }
}

pub fn create_mail_transport() -> AsyncSmtpTransport<Tokio1Executor> {
    let config = get_config().expect("Failed to read configuration.");
    let server = config.email_settings.email_server;
    let user = config.email_settings.email_user;
    let pass = config.email_settings.email_pass.expose_secret();
    let creds = Credentials::new(user.to_string(), pass.to_string());
    AsyncSmtpTransport::<Tokio1Executor>::relay(&server)
        .unwrap()
        .credentials(creds)
        .build()
}
