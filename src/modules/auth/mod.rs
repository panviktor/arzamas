use crate::core::middleware::rate_limiter;
/// Module that contains all the functions related to authentication.
use actix_web::web;
use hex::encode;
use sha2::{Digest, Sha256};

use crate::err_server;
use crate::models::ServerError;

pub mod controllers;

pub mod credentials;
pub mod email;
pub mod middleware;
pub mod models;
pub mod service;
pub mod session;
pub mod totp;
pub(crate) mod utils;

pub fn init_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .wrap(rate_limiter::RateLimitServices {
                requests_count: 200,
            })
            .service(
                web::resource("/create")
                    .wrap(rate_limiter::RateLimitServices {
                        requests_count: 100,
                    })
                    .route(web::post().to(controllers::create_user)),
            )
            .service(
                web::resource("/verify-email")
                    .wrap(rate_limiter::RateLimitServices {
                        requests_count: 100,
                    })
                    .route(web::post().to(controllers::verify_email)),
            )
            .service(
                web::resource("/login")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 50 })
                    .route(web::post().to(controllers::login)),
            )
            .service(
                web::resource("/forgot-password")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 25 })
                    .route(web::post().to(controllers::forgot_password)),
            )
            .service(
                web::resource("/password-reset")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 25 })
                    .route(web::post().to(controllers::password_reset)),
            )
            .service(
                web::resource("/login-2fa")
                    .wrap(rate_limiter::RateLimitServices { requests_count: 50 })
                    .route(web::post().to(controllers::login_2fa)),
            ),
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
