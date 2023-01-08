/// Module for the struct that represents a single user.

use serde::{Serialize};
use chrono::{ NaiveDateTime };
use entity::user::Model;

/// Holds a single user's information.
#[derive(Serialize, Debug, Clone)]
pub struct User {
    /// Random user ID that is unique.
    /// Used to identify the user so that email and username can be changed without issue
    pub user_id: String,
    /// User email
    pub email: String,
    /// User selected username
    pub username: String,
    /// The hash of the password for the user (using Argon2)
    pub pass_hash: String,
    /// Whether or not the user's email is validated.
    pub email_validated: bool,
    /// Whether or not the user is using 2fa on their account
    pub totp_active: bool,
    /// Their TOTP token
    pub totp_token: Option<String>,
    /// The TOTP backup codes (hashed with SHA256)
    pub totp_backups: Option<String>,
    /// The date of created
    pub created_at: NaiveDateTime
}

impl User {
    pub(crate) fn from_orm(data: Model) -> User {
        User {
            user_id: data.user_id,
            email: data.email,
            username: data.username,
            pass_hash: data.pass_hash,
            email_validated: data.email_validated,
            totp_active: data.totp_active,
            totp_token: data.totp_token,
            totp_backups: data.totp_backups,
            created_at: data.created_at.into()
        }
    }
}