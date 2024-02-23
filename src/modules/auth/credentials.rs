use crate::models::ServerError;
use crate::modules::auth::utils::{get_user_by_email, get_user_by_username};
use crate::{err_input, err_server};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
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
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let normalize_password = normalize_string(password);
    let password_hash = argon2.hash_password(normalize_password.as_bytes(), &salt);

    match password_hash {
        Ok(hash) => Ok(hash.to_string()),
        Err(e) => Err(err_server!("Error generating hash: {}", e)),
    }
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
pub fn credential_validator(password_hash: &str, password: &str) -> Result<bool, ServerError> {
    // Normalize the input password
    let normalize_password = normalize_string(password);

    // Parse the stored password hash
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(hash) => hash,
        Err(_) => return Err(err_server!("Invalid hash format.")),
    };
    // Create an instance of the Argon2 algorithm
    let argon2 = Argon2::default();

    // Verify the password against the stored hash
    match argon2.verify_password(normalize_password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),  // Password matches
        Err(_) => Ok(false), // Password does not match or other error
    }
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
            return match credential_validator(&user.pass_hash, &password)? {
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
