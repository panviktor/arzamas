use chrono::{Duration, Utc};

use lettre::{
    message::{header, SinglePart},
    AsyncTransport, Message as LettreMessage,
};
use sea_orm::DatabaseConnection;

use crate::core::config::get_config;
use crate::core::error::ServerError;
use crate::err_server;
use crate::infrastructure::email::email::MAILER;

use crate::modules_deprecated::auth::utils::{
    add_email_token, add_password_reset_token, find_email_verify_token, verify_email_by,
};

/// Send a verification email to the supplied email.
pub async fn send_verification_email(to_email: &str, token: &str) -> Result<(), ServerError> {
    let config = get_config().expect("Failed to read configuration.");
    let from = config.email_settings.email_from;

    let text = format!(
        "This email was used to register for the Arzamas App.\n\
             To verify your email copy your token to app! \n\
             Token: {}\n\
             This token will expire in 24 hours.",
        token
    );

    let email = LettreMessage::builder()
        .from(format!("Sender <{}>", from).parse().unwrap())
        .to(format!("Receiver <{}>", to_email).parse().unwrap())
        .subject("Authentication: Email Verification.")
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(text),
        )
        .map_err(|e| err_server!("Problem send email {}", e))?;

    // Open a remote connection to gmail
    let mailer = &MAILER;

    // Send the email
    match mailer.send(email).await {
        Ok(_) => {
            tracing::debug!("Email sent successfully!");
            Ok(())
        }
        Err(e) => Err(err_server!("Error unlocking mailer: {}", e)),
    }
}

pub async fn send_password_reset_email(
    user_id: &str,
    to_email: &str,
    db: &DatabaseConnection,
) -> Result<(), ServerError> {
    let mut password_reset_token = "".to_string();
    let mut error: Option<ServerError> = None;

    let config = get_config().expect("Failed to read configuration.");
    let from = config.email_settings.email_from;

    for i in 0..10 {
        // password_reset_token = super::generate_token()?;
        // match add_password_reset_token(
        //     user_id,
        //     &password_reset_token,
        //     Utc::now() + Duration::days(1),
        //     db,
        // )
        //     .await
        // {
        //     Ok(_) => {
        //         error = None;
        //         break;
        //     }
        //     Err(e) => {
        //         log::warn!(
        //             "Problem creating password reset token for user {} (attempt {}/10): {}",
        //             user_id,
        //             i + 1,
        //             e
        //         );
        //         error = Some(e);
        //     }
        // }
    }

    if let Some(e) = error {
        return Err(err_server!("Error generating password reset token: {}", e));
    }

    let text = format!(
        "The account associated with this email has had a password reset request\n\
             To reset your password copy your token to app! \n\
             Token: {}\n\
             User_id: {}\n\
             This token will expire in 24 hours.",
        password_reset_token, user_id
    );

    let email = LettreMessage::builder()
        .from(format!("Sender <{}>", from).parse().unwrap())
        .to(format!("Receiver <{}>", to_email).parse().unwrap())
        .subject("Arzamas authentication: Reset password.")
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(text),
        )
        .map_err(|e| err_server!("Problem send email {}", e))?;

    // Open a remote connection to gmail
    let mailer = &MAILER;

    // Send the email
    match mailer.send(email).await {
        Ok(_) => {
            tracing::debug!("Email sent successfully!");
            Ok(())
        }
        Err(e) => Err(err_server!("Error unlocking mailer: {}", e)),
    }
}

/// Generate an email token and then send a verification email.
pub async fn send_validate_email(
    user_id: &str,
    email: &str,
    user_exists: bool,
    db: &DatabaseConnection,
) -> Result<(), ServerError> {
    let mut insert_error: Option<ServerError> = None;
    let mut email_token = "".to_string();

    for i in 0..10 {
        email_token = super::generate_email_verification_code()?;
        match add_email_token(
            user_id,
            email,
            &email_token,
            Utc::now() + Duration::days(1),
            user_exists,
            db,
        )
        .await
        {
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
    token: &str,
    db: &DatabaseConnection,
) -> Result<(), ServerError> {
    let verification = find_email_verify_token(email, db).await;
    match verification {
        Ok(model) => {
            let now = Utc::now().naive_utc();
            if model.otp_hash == token && model.expiry > now {
                return verify_email_by(&model.user_id, db).await;
            }
            Err(err_server!("Problem: expiry or invalid code from email!"))
        }
        Err(_) => Err(err_server!("Problem finding email and token {}", email)),
    }
}

pub async fn send_totp_email_code(
    email: &str,
    code: &str,
    user_id: &str,
) -> Result<(), ServerError> {
    let config = get_config().expect("Failed to read configuration.");
    let from = config.email_settings.email_from;
    let text = format!(
        "An email has been sent to the account linked with your profile containing a confirmation code for two-factor authentication.\n
         If you did not initiate the login, it is crucial that you reset your password immediately.\n
         Your login ID and confirmation code are included in the email.\n\
            Code: {}\n\
            User Id: {}\n\
            This code will expire in 5 minutes.", code, user_id
    );

    let email = LettreMessage::builder()
        .from(format!("Sender <{}>", from).parse().unwrap())
        .to(format!("Receiver <{}>", email).parse().unwrap())
        .subject("Authentication: 2FA Verification.")
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(text),
        )
        .map_err(|e| err_server!("Problem send 2FA Verification email {}:{}", user_id, e))?;

    match MAILER.send(email).await {
        Ok(_) => {
            tracing::debug!("Email sent successfully!");
            Ok(())
        }
        Err(e) => Err(err_server!("Problem send 2FA Verification email: {}", e)),
    }
}

pub async fn success_enter_email(email: &str, login_ip: &str) -> Result<(), ServerError> {
    let config = get_config().expect("Failed to read configuration.");
    let from = config.email_settings.email_from;

    let now = Utc::now().naive_utc();
    let text = format!(
        "Hello, {}! Someone signed in to your account!\n\
         Date: {}\n\
         IP: {}\n",
        email, now, login_ip
    );

    let email = LettreMessage::builder()
        .from(format!("Sender <{}>", from).parse().unwrap())
        .to(format!("Receiver <{}>", email).parse().unwrap())
        .subject("Login to your account.")
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(text),
        )
        .map_err(|e| err_server!("Problem login email {}", e))?;

    let mailer = &MAILER;
    match mailer.send(email).await {
        Ok(_) => {
            tracing::debug!("Email sent successfully!");
            Ok(())
        }
        Err(e) => Err(err_server!("Problem login email: {}", e)),
    }
}
