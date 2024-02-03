use crate::core::middleware::rate_limiter;
use crate::modules::auth::middleware;
use actix_web::web;
pub mod controllers;
pub mod models;
mod service;
mod utils;

pub fn init_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/user")
            .wrap(middleware::AuthCheckService)
            .wrap(rate_limiter::RateLimitServices {
                requests_count: 500,
            })
            .service(web::resource("/about-me").route(web::get().to(controllers::about_me)))
            // Sessions block
            .service(web::resource("/logout").route(web::post().to(controllers::logout)))
            .service(web::resource("/logout-all").route(web::post().to(controllers::logout_all)))
            .service(
                web::resource("/current-session")
                    .route(web::get().to(controllers::current_session)),
            )
            .service(web::resource("/all-sessions").route(web::get().to(controllers::all_sessions)))
            // Reset password block
            .service(
                web::resource("/change-password")
                    .route(web::post().to(controllers::change_password)),
            )
            .service(
                web::resource("/change-email").route(web::post().to(controllers::change_email)),
            )
            .service(
                web::resource("/resend-verify-email")
                    .route(web::post().to(controllers::resend_verify_email)),
            )
            // 2FA
            .service(
                web::resource("/security-settings")
                    .route(web::get().to(controllers::get_security_settings)),
            )
            .service(
                web::resource("/security-settings")
                    .route(web::post().to(controllers::update_security_settings)),
            )
            .service(
                web::resource("/2fa-add-email").route(web::post().to(controllers::add_email_2fa)),
            )
            .service(
                web::resource("/2fa-remove-email")
                    .route(web::post().to(controllers::remove_email_2fa)),
            )
            .service(web::resource("/2fa-add").route(web::post().to(controllers::add_2fa)))
            .service(
                web::resource("/2fa-activate").route(web::post().to(controllers::activate_2fa)),
            )
            .service(web::resource("/2fa-reset").route(web::post().to(controllers::reset_2fa)))
            .service(web::resource("/2fa-remove").route(web::post().to(controllers::remove_2fa))),
    );
}
