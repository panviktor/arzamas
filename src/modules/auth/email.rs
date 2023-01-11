// use crate::db::email::{add_email_token, add_password_reset_token};
use crate::models::ServerError;
/// Module containing the email sending related functions.


use crate::core::{config};

use chrono::{Duration, Utc};
use lazy_static::lazy_static;
// use lettre::{smtp::authentication::Credentials, SmtpClient, SmtpTransport, Transport};
// use lettre_email::EmailBuilder;
use std::sync::Mutex;

// lazy_static! {
//     static ref MAILER: Mutex<SmtpTransport> = Mutex::new(
//         SmtpClient::new_simple(config::EMAIL_SERVER.as_str())
//             .unwrap()
//             .credentials(Credentials::new(
//                 config::EMAIL_USER.to_string(),
//                 config::EMAIL_PASS.to_string(),
//             ))
//             .transport()
//     );
// }


/// Generate an email token and then send a verification email.
pub async fn validate_email(user_id: &str, email: &str) -> Result<(), ServerError> {
    let mut insert_error: Option<ServerError> = None;
    let mut email_token = "".to_string();
    // for i in 0..10 {
    //     email_token = super::generate_token()?;
    //     match add_email_token(user_id, email, &email_token, Utc::now() + Duration::days(1)).await {
    //         Ok(_) => {
    //             insert_error = None;
    //             break;
    //         }
    //         Err(e) => {
    //             log::warn!(
    //                 "Problem creating email token for new validation {} (attempt {}/10): {}",
    //                 email_token,
    //                 i + 1,
    //                 e
    //             );
    //             insert_error = Some(e);
    //         }
    //     }
    // }
    // if let Some(e) = insert_error {
    //     return Err(err_server!(
    //         "Error generating email verification token: {}",
    //         e
    //     ));
    // }
    // send_verification_email(email, &email_token)?;
    Ok(())
}