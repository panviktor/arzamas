/// Module that contains all the functions related to authentication.
use actix_web::{ web, guard};
use hex::encode;
use sha2::{Digest, Sha256};

use crate::err_server;
use crate::models::ServerError;

mod controller;

pub mod service;
pub mod email;
pub mod credentials;
pub mod session;
pub mod middleware;

pub fn init_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .guard(guard::Header("content-type", "application/json"))
            .service(
                web::resource("/create")
                        .route(web::post().to(controller::create_user))
            )
            .service(
                web::resource("/verify_email")
                    .route(web::post().to(controller::verify_email))
            )
            .service(
                web::resource("/login")
                    .route(web::post().to(controller::login))
            )
    );
}

/// Generate a generic 32 byte token, and convert it to a hex string.
pub fn generate_token() -> Result<String, ServerError> {
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token).map_err(|e| err_server!("Error generating token: {}", e))?;
    Ok(encode(token.to_vec()))
}

/// Generate a generic 32 byte token, and convert it to a hex string.
pub fn generate_email_verification_code() -> Result<String, ServerError> {
    let mut token = [0u8; 8];
    getrandom::getrandom(&mut token).map_err(|e| err_server!("Error generating token: {}", e))?;
    Ok(encode(token.to_vec()))
}

/// Hash a token with SHA256.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    encode(hasher.finalize())
}
