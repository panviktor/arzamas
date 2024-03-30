use crate::core::error::ServerError;
// use crate::modules::auth::utils::{get_user_by_email, get_user_by_username};
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

// Generate a random user ID
//Check if the username + password pair are valid
// pub fn credential_validator(password_hash: &str, password: &str) -> Result<bool, ServerError> {
// Normalize the input password
// let normalize_password = normalize_string(password);
//
// // Parse the stored password hash
// let parsed_hash = match PasswordHash::new(password_hash) {
//     Ok(hash) => hash,
//     Err(_) => return Err(err_server!("Invalid hash format.")),
// };
// // Create an instance of the Argon2 algorithm
// let argon2 = Argon2::default();
//
// // Verify the password against the stored hash
// match argon2.verify_password(normalize_password.as_bytes(), &parsed_hash) {
//     Ok(()) => Ok(true),  // Password matches
//     Err(_) => Ok(false), // Password does not match or other error
// }

//     Ok(false)
// }

// Check if the username + password pair are valid
// pub async fn credential_validator_username_email(
//     identifier: &str,
//     password: &str,
//     db: &DatabaseConnection,
// ) -> Result<Option<User>, ServerError> {
// let user = match EMAIL_REGEX.is_match(identifier) {
//     true => get_user_by_email(identifier, db).await,
//     false => get_user_by_username(identifier, db).await,
// };
//
// if let Ok(user) = user {
//     if let Some(user) = user {
//         return match credential_validator(&user.pass_hash, &password)? {
//             true => Ok(Some(user)),
//             false => {
//                 tracing::warn!("User doesn't exist: {}", identifier);
//                 Ok(None)
//             }
//         };
//     }
// }
// tracing::warn!("User doesn't exist: {}", identifier);
//     return Err(err_input!("User doesn't exist!"));
// }
