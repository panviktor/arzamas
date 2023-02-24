pub mod general_handlers;
pub mod auth;
pub mod user;
pub mod notes;

use uuid::Uuid;
use chrono::{Utc, TimeZone};
use hex::encode;
use sha2::{Digest, Sha512};

fn generate_unique_id() -> String {
    // Generate a new UUID
    let uuid = Uuid::new_v4().to_string();
    // Get the current date and time in UTC
    let utc_time = Utc::now();
    // Concatenate the UUID with the date and time in ISO-8601 format
    let id_str = format!("{}-{}", uuid, utc_time.to_rfc3339());
    // Compute a SHA-256 hash of the concatenated string
    let mut hasher = Sha512::new();
    hasher.update(id_str.as_bytes());
    encode(hasher.finalize())
}