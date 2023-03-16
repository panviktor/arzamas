use chrono::{Duration, Utc};
use lazy_static::lazy_static;
use crate::core::config::{get_config,};
use crate::models::ServerError;
use crate::core::email::{add_email_token, find_email_verify_token, verify_email_by};
use crate::err_server;

use lettre::{
    message::{header, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message as LettreMessage, Tokio1Executor,
};
use secrecy::ExposeSecret;

lazy_static! {
    static ref MAILER: AsyncSmtpTransport<Tokio1Executor> = {
        async_std::task::block_on(async {
            let config = get_config().expect("Failed to read configuration.");
            let server = config.email_settings.email_server;
            let user = config.email_settings.email_user;
            let pass = config.email_settings.email_pass.expose_secret();
            let creds = Credentials::new(user.to_string(), pass.to_string());
             AsyncSmtpTransport::<Tokio1Executor>::relay(&server)
                .unwrap()
                .credentials(creds)
                .build()
        })
    };
}

/// Send a verification email to the supplied email.
 pub async fn send_verification_email(to_email: &str, token: &str) -> Result<(), ServerError> {

    let config = get_config().expect("Failed to read configuration.");
    let from = config.email_settings.email_from;

    let text = format!(
            "This email was used to register for the Arzamas App.\n\
             To verify your email copy your token to app! \n\
             Token: {}\n\
             This token will expire in 24 hours.",  token
    );

    let email = LettreMessage::builder()
        .from(format!("Sender <{}>", from).parse().unwrap())
        .to(format!("Receiver <{}>", to_email)
        .parse().unwrap())
        .subject("Authentication: Email Verification.")
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(text),
        )
        .unwrap();

// Open a remote connection to gmail
    let mailer = &MAILER;

// Send the email
    match mailer.send(email).await {
        Ok(_) => {
            tracing::debug!("Email sent successfully!");
            Ok(())
        }
        Err(e) => Err(err_server!("Error unlocking mailer: {}", e))
    }
}

// Send a password reset email.
// pub async fn send_password_reset_email(user_id: &str, email: &str) -> Result<(), ServerError> {
    // let mut password_reset_token = "".to_string();
    // let mut error: Option<ServerError> = None;
    // for i in 0..10 {
    //     password_reset_token = super::generate_token()?;
    //     match add_password_reset_token(
    //         user_id,
    //         &password_reset_token,
    //         Utc::now() + Duration::days(1),
    //     )
    //         .await
    //     {
    //         Ok(_) => {
    //             error = None;
    //             break;
    //         }
    //         Err(e) => {
    //             log::warn!(
    //                 "Problem creating password reset token for user {} (attempt {}/10): {}",
    //                 user_id,
    //                 i + 1,
    //                 e
    //             );
    //             error = Some(e);
    //         }
    //     }
    // }
    // if let Some(e) = error {
    //     return Err(err_server!("Error generating password reset token: {}", e));
    // }
    // let email = EmailBuilder::new()
    //     .to(email)
    //     .from(config::EMAIL_FROM.as_str())
    //     .subject("Rust Authentication Example: Password Reset")
    //     .text(format!("The account associated with this email has had a password reset request. Click this link to reset the password: {}password-reset?token={}\nThis link will expire in 24 hours.", config::DOMAIN.as_str(), password_reset_token))
    //     .build()
    //     .unwrap();
    //
    // let result = MAILER
    //     .lock()
    //     .map_err(|e| err_server!("Error unlocking mailer: {}", e))?
    //     .send(email.into());
    //
    // if result.is_ok() {
    //     log::debug!("Email sent");
    // } else {
    //     log::warn!("Could not send email: {:?}", result);
    // }
//     Ok(())
// }

/// Generate an email token and then send a verification email.
pub async fn validate_email(
    user_id: &str,
    email: &str,
    user_exists: bool
) -> Result<(), ServerError> {
    let mut insert_error: Option<ServerError> = None;
    let mut email_token = "".to_string();

    for i in 0..10 {
        email_token = super::generate_email_verification_code()?;
        match add_email_token(user_id, email, &email_token, Utc::now() + Duration::days(1), user_exists).await {
            Ok(_) => {
                insert_error = None;
                break;
            }
            Err(e) => {
                log::warn!(
                    "Problem creating email token for new validation {} (attempt {}/10): {}",
                    email_token,
                    i + 1,
                    e
                );
                insert_error = Some(e);
            }
        }
    }
    if let Some(e) = insert_error {
        return Err(err_server!(
            "Error generating email verification token: {}",
            e
        ));
    }
    send_verification_email(email, &email_token).await?;
    Ok(())
}

pub async fn verify_user_email(
    email: &str,
    token: &str
) -> Result<(), ServerError> {
    let verification = find_email_verify_token(email).await;
    match verification {
        Ok(model) => {
            let now = Utc::now().naive_utc();
            if model.otp_hash == token && model.expiry > now {
                return verify_email_by(&model.user_id).await
            }
            Err(err_server!("Problem: expiry or invalid code from email!"))
        }
        Err(_) => { Err(err_server!("Problem finding email and token {}", email)) }
    }
}