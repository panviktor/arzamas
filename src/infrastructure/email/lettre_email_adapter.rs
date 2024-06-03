use crate::core::config::get_config;
use crate::domain::error::DomainError;
use crate::domain::ports::email::email::EmailPort;
use crate::infrastructure::email::error::EmailError;
use async_trait::async_trait;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
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
