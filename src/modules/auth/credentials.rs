use crate::models::ServerError;
use crate::modules::auth::utils::{get_user_by_email, get_user_by_username};
use crate::{err_input, err_server};
use argon2::{hash_encoded, verify_encoded, Config};
use entity::user::Model as User;
use lazy_static::lazy_static;
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use sea_orm::DatabaseConnection;
use unicode_normalization::UnicodeNormalization;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^([a-z0-9_+]([a-z0-9_+.-]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
    )
    .unwrap();
}

/// Normalize a unicode string
fn normalize_string(s: &str) -> String {
    s.nfkc().collect::<String>()
}

/// Generate a password hash from the supplied password, using a random salt
pub fn generate_password_hash(password: &str) -> Result<String, ServerError> {
    let config = Config::default();
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).map_err(|e| err_server!("Error generating salt: {}", e))?;
    hash_encoded(normalize_string(password).as_bytes(), &salt, &config)
        .map_err(|e| err_server!("Error generating hash: {}", e))
}

/// Generate a random user ID
pub fn generate_user_id() -> Result<String, ServerError> {
    let str: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(3)
        .map(char::from)
        .collect();
    let mut token =
        super::generate_token().map_err(|e| err_server!("Error generate user_id: {}", e))?;
    token.push_str(&*str);
    Ok(token)
}

/// Check if the username + password pair are valid
pub fn credential_validator(user: &User, password: &str) -> Result<bool, ServerError> {
    Ok(
        verify_encoded(&user.pass_hash, normalize_string(password).as_bytes())
            .map_err(|e| err_server!("Error verifying hash: {}", e))?,
    )
}

/// Check if the username + password pair are valid
pub async fn credential_validator_username_email(
    identifier: &str,
    password: &str,
    db: &DatabaseConnection,
) -> Result<Option<User>, ServerError> {
    let user = match EMAIL_REGEX.is_match(identifier) {
        true => get_user_by_email(identifier, db).await,
        false => get_user_by_username(identifier, db).await,
    };

    if let Ok(user) = user {
        if let Some(user) = user {
            return match credential_validator(&user, &password)? {
                true => Ok(Some(user)),
                false => {
                    tracing::warn!("User doesn't exist: {}", identifier);
                    Ok(None)
                }
            };
        }
    }
    tracing::warn!("User doesn't exist: {}", identifier);
    return Err(err_input!("User doesn't exist!"));
}

/// Check that a password meets password requirements
pub fn validate_password_rules(password: &str, password_confirm: &str) -> Result<(), ServerError> {
    if password.len() < 10 {
        return Err(err_input!("Password must be at least 10 characters."));
    }
    if password.bytes().len() > 8192 {
        return Err(err_input!("Password too long (> 8192 bytes)."));
    }
    if password != password_confirm {
        return Err(err_input!("Passwords don't match."));
    }
    Ok(())
}

/// Check that a username meets username requirements
pub fn validate_username_rules(username: &str) -> Result<(), ServerError> {
    if username.len() <= 0 {
        return Err(err_input!("Username cannot be empty."));
    }
    if username.len() <= 3 {
        return Err(err_input!("Username cannot be short."));
    }
    if username.bytes().len() > 8192 {
        return Err(err_input!("Username too long (> 8192 bytes)."));
    }
    if EMAIL_REGEX.is_match(username) {
        return Err(err_input!("Username may not be an email."));
    }
    Ok(())
}

/// Check that an email meets email requirements
pub fn validate_email_rules(email: &str) -> Result<(), ServerError> {
    if !EMAIL_REGEX.is_match(email) {
        return Err(err_input!("Invalid email."));
    }
    Ok(())
}
